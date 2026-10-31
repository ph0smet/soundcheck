open Soundcheck_kong

(* YAML 1.2.2 §5.7 defines these four NUL escapes. Expectations are literal
   decoded bytes, not a round trip through the same YAML binding. libyaml's
   length-bearing scalar API preserves the suffix; ocaml-yaml 3.2.0 does not.
   See docs/plans/2026-10-yaml-scalar-fidelity.md for the source assessment. *)

let checks = ref 0
let fail label message = failwith (label ^ ": " ^ message)

let reject label source =
  incr checks;
  match Parse.yaml_value ~where:"test" source with
  | Error _ -> ()
  | Ok _ -> fail label "accepted a scalar whose bytes cannot be preserved"

let accept label source expected =
  incr checks;
  match Parse.yaml_value ~where:"test" source with
  | Ok actual when actual = expected -> ()
  | Ok _ -> fail label "changed decoded bytes"
  | Error error -> fail label error

let string label source expected = accept label source (`String expected)

let utf16 ~little source =
  let buffer = Buffer.create (2 * String.length source + 2) in
  Buffer.add_string buffer (if little then "\xff\xfe" else "\xfe\xff");
  let rec append index =
    if index < String.length source then begin
      let decoded = String.get_utf_8_uchar source index in
      assert (Uchar.utf_decode_is_valid decoded);
      (if little then Buffer.add_utf_16le_uchar else Buffer.add_utf_16be_uchar)
        buffer (Uchar.utf_decode_uchar decoded);
      append (index + Uchar.utf_decode_length decoded)
    end
  in
  append 0;
  Buffer.contents buffer

let () =
  List.iter
    (fun escape ->
      reject (escape ^ " in value") ("{name: \"before" ^ escape ^ "after\"}");
      reject (escape ^ " in key") ("{\"before" ^ escape ^ "after\": value}");
      reject (escape ^ " at start") ("\"" ^ escape ^ "after\"");
      reject (escape ^ " at end") ("\"before" ^ escape ^ "\"");
      reject (escape ^ " in ignored field")
        ("{services: [], ignored: {nested: [\"before" ^ escape ^ "after\"]}}");
      string (escape ^ " plain") ("before" ^ escape ^ "after")
        ("before" ^ escape ^ "after");
      string (escape ^ " single-quoted") ("'before" ^ escape ^ "after'")
        ("before" ^ escape ^ "after");
      string (escape ^ " literal block") ("|-\n  before" ^ escape ^ "after\n")
        ("before" ^ escape ^ "after");
      string (escape ^ " folded block") (">-\n  before" ^ escape ^ "after\n")
        ("before" ^ escape ^ "after");
      string (escape ^ " escaped slash") ("\"before\\" ^ escape ^ "after\"")
        ("before" ^ escape ^ "after");
      string (escape ^ " in comment") ("# " ^ escape ^ "\n\"kept\"") "kept";
      reject (escape ^ " after escaped slash")
        ("\"before\\\\" ^ escape ^ "after\""))
    [ "\\0"; "\\x00"; "\\u0000"; "\\U00000000" ];

  List.iter
    (fun (label, source, expected) -> string label source expected)
    [ ("escaped quote", {|"before\"after"|}, "before\"after");
      ("escaped slash", {|"before\\after"|}, "before\\after");
      ("hex backslash does not re-escape", {|"\x5c0"|}, "\\0");
      ("Unicode backslash does not re-escape", {|"\u005cu0000"|}, "\\u0000");
      ("other control escapes", {|"\x01\u0002\U00000003"|}, "\001\002\003");
      ("ordinary escapes", {|"\t\r\n"|}, "\t\r\n");
      ("Unicode escapes", {|"\u00e9\U0001f600"|}, "é😀");
      ("anchor", "&kept \"before\\nnext\"", "before\nnext");
      ("anchor with comment", "&kept # \\u0000 is literal here\n  \"value\"", "value");
      ("line continuation", "\"before\\\n  after\"", "beforeafter");
      ("CRLF continuation", "\"before\\\r\n  after\"", "beforeafter") ];

  let before = "# café 😀\r\nclé: \"safe\"\r\nother: " in
  let value = before ^ "\"before\\u0000after\"" in
  let safe = before ^ "\"before\\u0001after\"" in
  let expected = `O [ ("clé", `String "safe"); ("other", `String "before\001after") ] in
  List.iter
    (fun (label, encode) ->
      reject (label ^ " position after non-ASCII") (encode value);
      accept (label ^ " preserved non-ASCII and escape") (encode safe) expected;
      reject (label ^ " raw NUL") (encode "{name: before\000after}");
      reject (label ^ " raw NUL after document") (encode "{}\n...\n\000"))
    [ ("UTF-8", Fun.id);
      ("UTF-8 BOM", (fun source -> "\xef\xbb\xbf" ^ source));
      ("UTF-16LE", utf16 ~little:true);
      ("UTF-16BE", utf16 ~little:false) ];
  List.iter (fun (label, encode) ->
    string (label ^ " line-start BOM after anchor") (encode "&kept\n\xef\xbb\xbf\"before\\nnext\"") "before\nnext";
    reject (label ^ " NUL after anchor and line-start BOM") (encode "&kept\n\xef\xbb\xbf\"before\\u0000after\""))
    [ "UTF-8", Fun.id;
      "UTF-8 BOM", (fun source -> "\xef\xbb\xbf" ^ source);
      "UTF-16LE", utf16 ~little:true;
      "UTF-16BE", utf16 ~little:false ];
  reject "NUL after Unicode within a scalar" "\"café 😀\\u0000suffix\"";
  reject "NUL after escaped quote" {|"before\"\0after"|};
  reject "NUL after line continuation" "\"before\\\n  \\u0000after\"";
  reject "NUL after anchor" "&kept \"before\\0after\"";
  reject "NUL after anchored comment" "&kept # literal \\0\n \"\\0value\"";
  reject "invalid UTF-8" "\"\xc3\x28\"";
  reject "incomplete UTF-16" "\xff\xfe\x22";

  incr checks;
  (match Parse.parse_string {|plugins: [{name: "key-auth\u0000custom"}]|} with
   | Error _ -> ()
   | Ok _ -> fail "plugin identity" "truncated plugin must not become key-auth");
  incr checks;
  (match Contract_spec.parse_string
     {|schema_version: 1
kind: authenticated-access
scope: {path_prefix: /admin, method: "GET\u0000POST"}
|} with
   | Error _ -> ()
   | Ok _ -> fail "frozen identity" "truncated scope must not become GET");
  Printf.printf "Scalar fidelity: %d checks passed\n" !checks
