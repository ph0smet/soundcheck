open Soundcheck_core
open Soundcheck_kong

let expect_normalized raw expected =
  let actual = Path_normalization.normalize_literal raw in
  if actual <> expected then
    failwith
      (Printf.sprintf "normalize %S: expected %S, got %S" raw expected actual);
  if not (Path_normalization.is_normalized_request_path expected) then
    failwith (Printf.sprintf "normalized output %S is outside request domain" expected)

let expect_not_normalized path =
  if Path_normalization.is_normalized_request_path path then
    failwith (Printf.sprintf "unnormalized request path accepted: %S" path)

let contains haystack needle =
  let haystack_length = String.length haystack in
  let needle_length = String.length needle in
  let rec search offset =
    offset + needle_length <= haystack_length
    && (String.sub haystack offset needle_length = needle || search (offset + 1))
  in
  needle_length = 0 || search 0

(* Snapshot of the v11 request language before factoring the leading slash.
   Keep this independent of the production AST so the equality check detects
   widening or shrinking any part of the domain, at every string length. *)
let unfactored_request_path_language =
  let reserved_percent =
    "!*'();:@&=+$,/?%#[]" |> String.to_seq |> List.of_seq
    |> List.map (fun character ->
           Regex.Lit (Printf.sprintf "%%%02X" (Char.code character)))
    |> fun alternatives -> Regex.Alt alternatives
  in
  let non_dot_token =
    Regex.Alt
      [ Regex.Class (true, [ ('/', '/'); ('%', '%'); ('.', '.') ]);
        reserved_percent ]
  in
  let token = Regex.Alt [ Regex.Lit "."; non_dot_token ] in
  let segment =
    Regex.Alt
      [ Regex.Concat [ non_dot_token; Regex.Star token ];
        Regex.Concat [ Regex.Lit "."; non_dot_token; Regex.Star token ];
        Regex.Concat [ Regex.Lit ".."; token; Regex.Star token ] ]
  in
  Regex.Alt
    [ Regex.Lit "/";
      Regex.Concat
        [ Regex.Lit "/"; segment;
          Regex.Star (Regex.Concat [ Regex.Lit "/"; segment ]);
          Regex.Opt (Regex.Lit "/") ] ]

let check_request_language () =
  let language = Regex.to_smt Path_normalization.request_path_language in
  let equivalence =
    Printf.sprintf
      "(set-logic ALL)\n(assert (distinct %s %s))\n(check-sat)\n"
      (Regex.to_smt unfactored_request_path_language) language
  in
  (match Solve.check equivalence with
   | Solve.Proved -> ()
   | result ->
     failwith ("request language changed: " ^ Solve.string_of_result result));

  (* Explicit expectations from Kong's URI normalization rules: standalone dot
     segments disappear, reserved escapes retain uppercase hex, other escapes
     decode, and duplicate slashes collapse. Language equality alone would
     preserve any pre-existing error, so also check these boundary cases. *)
  let cases =
    List.map (fun path -> (path, true))
      [ "/"; "/a"; "/a/"; "/.a"; "/..a"; "/..."; "/.../";
        "/.%2F"; "/..%2F"; "/a/.b/..c/.../";
        "/admin/config.json"; "/a-b_c/~user/50%25";
        "/a%2Fb"; "/%25"; "/endeløst" ]
    @ List.map (fun path -> (path, false))
      [ ""; "a"; "/."; "/.."; "/a/."; "/a/.."; "/./a"; "/../a";
        "//"; "/a//b"; "/a//"; "/%2E"; "/%41"; "/%2f";
        "/%"; "/%2"; "/%GG"; "/a%zz" ]
  in
  List.iter
    (fun (path, expected) ->
      if Path_normalization.is_normalized_request_path path <> expected then
        failwith (Printf.sprintf "request-domain membership for %S" path))
    cases;
  let disagreements =
    List.map
      (fun (path, expected) ->
        Printf.sprintf "(not (= (str.in_re %s %s) %b))"
          (Regex.smt_string path) language expected)
      cases
    |> String.concat " "
  in
  let query =
    "(set-logic ALL)\n(assert (or " ^ disagreements ^ "))\n(check-sat)\n"
  in
  match Solve.check query with
  | Solve.Proved -> ()
  | result ->
    failwith ("SMT request-domain boundary: " ^ Solve.string_of_result result)

let () =
  check_request_language ();
  (* Transcribed from Kong's kong.tools.uri unit cases. *)
  List.iter (fun (raw, expected) -> expect_normalized raw expected)
    [ ("/a%2fb%2fc/", "/a%2Fb%2Fc/");
      ("/f%6f%6f", "/foo");
      ("/%6B%6f%6e%67", "/kong");
      ("/%2E", "/");
      ("/./.././../", "/");
      ("/a/b/c/./../../g", "/a/g");
      ("/a//b//", "/a/b/") ];

  List.iter expect_not_normalized
    [ ""; "/a//b"; "/a/./b"; "/a/../b"; "/%2e"; "/%41";
      "/a%2fb"; "/a%zz" ];

  List.iter
    (fun path ->
      if not (Path_normalization.is_normalized_request_path path) then
        failwith (Printf.sprintf "canonical request path rejected: %S" path))
    [ "/"; "/admin"; "/a.../b"; "/a%2Fb"; "/endeløst" ];

  let impossible =
    Smt_encode.condition_query ~domain:Path_normalization.request_domain
      ~name:"normalized-domain" ~description:"exclude raw paths"
      (Ir.Path_exact "/admin/../secret")
    |> Solve.check
  in
  (match impossible with
   | Solve.Proved -> ()
   | _ -> failwith "SMT request domain admitted an unnormalized path");

  let outside_request : Ir.request =
    { object_request = None; principal = Anonymous;
      action = "GET";
      resource = "/raw/../path";
      context = [];
      source = 0l;
      host = "";
      scheme = "http";
      sni = "" }
  in
  let allow_by_default : Ir.policy =
    { request_domain = Path_normalization.request_domain;
      rules = [];
      default = Allow }
  in
  if Ir.evaluate allow_by_default outside_request <> Deny
     || Ir.definitely_allows allow_by_default outside_request
  then failwith "concrete policy evaluation admitted a request outside its domain";

  let invalid_config =
    "services: [{name: api, routes: [{name: bad, paths: [/admin/%2e%2e/secret]}]}]"
  in
  (match
     Verify.run ~property:(Verify.No_anonymous_access "/admin") invalid_config
   with
   | Error error when contains error "not normalized; use \"/secret\"" -> ()
   | Error error -> failwith ("unexpected invalid-path error: " ^ error)
   | Ok _ -> failwith "non-normalized literal Kong route path was accepted");

  (match
     Verify.run ~property:(Verify.No_anonymous_access "/admin/../secret")
       "services: []"
   with
   | Error error when contains error "property path_prefix" -> ()
   | Error error -> failwith ("unexpected property-scope error: " ^ error)
   | Ok _ -> failwith "non-normalized property scope was accepted");

  (* Percent signs in authored regexes are regex syntax, not URI escapes. *)
  (match
     Verify.run ~property:(Verify.No_anonymous_access "/admin")
       "services: [{name: api, routes: [{name: regex, paths: ['~/admin%bar']}]}]"
   with
   | Ok _ -> ()
   | Error error -> failwith ("regex path was URI-normalized: " ^ error))
