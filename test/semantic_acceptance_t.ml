open Soundcheck_kong

(* This is an inventory-integrity gate. It does not decide whether a cited
   source, regression, or finite target sample justifies a semantic claim. *)
exception Invalid_inventory of string

let reject where message = raise (Invalid_inventory (where ^ ": " ^ message))
let pinned_revision = "a643428bc4d5397152164a63bcc0f8bc65fce69d"
let routers = [ "traditional"; "traditional_compatible" ]
let source_prefix = "https://github.com/Kong/kong/blob/" ^ pinned_revision ^ "/"

let object_ where keys = function
  | `O fields ->
    let names = List.map fst fields in
    if List.length names <> List.length (List.sort_uniq String.compare names) then
      reject where "duplicate fields";
    List.iter (fun name ->
      if not (List.mem name keys) then reject where ("unknown field " ^ name)) names;
    List.iter (fun name ->
      if not (List.mem name names) then reject where ("missing field " ^ name)) keys;
    fields
  | _ -> reject where "expected object"

let field fields name = List.assoc name fields
let string where = function
  | `String value when String.trim value <> "" -> value
  | _ -> reject where "expected nonempty string"

let list where = function
  | `A values -> values
  | _ -> reject where "expected list"

let nonempty where values =
  if values = [] then reject where "must not be empty";
  values

let unique where values =
  if List.length values <> List.length (List.sort_uniq String.compare values) then
    reject where "duplicate values";
  values

let strings where value = list where value |> List.map (string where) |> unique where
let one_of where allowed value =
  let value = string where value in
  if not (List.mem value allowed) then reject where ("unexpected value " ^ value);
  value

let identifier value =
  value <> "" && String.for_all (function
    | 'a' .. 'z' | '0' .. '9' | '-' -> true | _ -> false) value

let relative_path where value =
  if not (Filename.is_relative value)
     || List.exists (fun part -> part = "" || part = "." || part = "..")
          (String.split_on_char '/' value)
     || not (String.for_all (function
          | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' | '-' | '.' | '/' -> true
          | _ -> false) value)
  then reject where "expected canonical repository-relative path";
  value

let contains source fragment =
  let rec search i =
    i + String.length fragment <= String.length source
    && (String.sub source i (String.length fragment) = fragment || search (i + 1))
  in
  search 0

let read_file path =
  let input = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in input)
    (fun () -> really_input_string input (in_channel_length input))

let local_file read where path =
  let path = relative_path where path in
  try ignore (read path); path
  with Sys_error _ -> reject where ("missing/unreadable local file " ^ path)

type probe = { name : string; model_class : string; flavor : string }

let valid_query value =
  let literal = String.for_all (function
      | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' | '-' -> true
      | _ -> false) in
  value = "" || value = "-"
  || List.for_all (fun pair -> match String.split_on_char '=' pair with
       | [ name; value ] -> name <> "" && literal name && literal value
       | _ -> false) (String.split_on_char '&' value)

let matrix_probes read matrix =
  if not (identifier matrix) then reject "probe.matrix" "expected matrix identifier";
  let base = "bench/kong/conformance/" in
  let config = if matrix = "routing" then "kong" else matrix in
  ignore (local_file read "probe.config" (base ^ config ^ ".yaml"));
  let path = base ^ (if matrix = "routing" then "probes" else matrix ^ "-probes") ^ ".tsv" in
  ignore (local_file read "probe.file" path);
  let rows = read path |> String.split_on_char '\n' in
  let probes = List.concat_map (fun row ->
    if row = "" || String.starts_with ~prefix:"#" row then []
    else
      let fields = String.split_on_char '|' row in
      let fields = if List.length fields = 15 then fields @ [ "" ] else fields in
      match fields with
      | [ name; _scheme; _method; _path; _host; _sni; _principal; _headers;
          _decision; _route; _service; _status; model_class; flavors; _source_ip; query ] ->
        if not (valid_query query)
           || (query <> "" && query <> "-" && matrix <> "termination")
        then reject path "invalid transport-only query";
        if name = "" || not (List.mem model_class [ "exact"; "conservative"; "unsupported" ])
        then reject path "invalid probe name/class";
        let selected = match flavors with
          | "both" -> routers
          | flavor when List.mem flavor routers -> [ flavor ]
          | _ -> reject path "invalid probe flavor"
        in
        List.map (fun flavor -> { name; model_class; flavor }) selected
      | _ -> reject path "expected 15 probe columns and optional query column") rows
  in
  ignore (nonempty path probes);
  ignore (unique path (List.map (fun p -> p.name ^ ":" ^ p.flavor) probes));
  probes

type stats = { features : int; source_only : int; modeled : int; boundary : int }

let validate read value =
  let root = object_ "inventory"
      [ "schema_version"; "profile"; "target"; "sources"; "controls"; "features" ] value in
  if field root "schema_version" <> `Float 1. then reject "schema_version" "expected 1";
  if field root "profile" <> `String Assurance.profile.id then
    reject "profile" "does not match the compiled assurance profile";
  let target = object_ "target" [ "version"; "revision"; "routers" ] (field root "target") in
  if field target "version" <> `String "3.9.3"
     || field target "revision" <> `String pinned_revision then
    reject "target" "expected the pinned Kong 3.9.3 revision";
  if List.sort String.compare (strings "target.routers" (field target "routers")) <> routers then
    reject "target.routers" "both supported router flavors are required";
  let catalogue where value = match value with
    | `O entries ->
      ignore (unique where (List.map fst entries));
      List.iter (fun (name, _) ->
        if not (identifier name) then reject where "invalid catalogue identifier") entries;
      entries
    | _ -> reject where "expected named catalogue"
  in
  let sources = catalogue "sources" (field root "sources") |> nonempty "sources" in
  List.iter (fun (name, value) ->
    let url = string ("sources." ^ name) value in
    if not (String.starts_with ~prefix:source_prefix url) then
      reject ("sources." ^ name) "expected immutable pinned Kong source URL";
    ignore (relative_path ("sources." ^ name)
      (String.sub url (String.length source_prefix) (String.length url - String.length source_prefix)))) sources;
  let controls = catalogue "controls" (field root "controls") in
  List.iter (fun (name, value) ->
    let where = "controls." ^ name in
    let control = object_ where [ "file"; "anchor"; "kind" ] value in
    let path = local_file read where (string where (field control "file")) in
    if not (String.starts_with ~prefix:"test/" path) then reject where "control must reference test/";
    ignore (one_of where [ "refinement-mutation"; "harness-mutation" ] (field control "kind"));
    let anchor = string where (field control "anchor") in
    if not (contains (read path) anchor) then reject where "control anchor is absent") controls;
  let expected =
    List.concat_map (fun (class_, features) ->
      List.map (fun (feature : Assurance.feature) -> feature.code, class_) features)
      [ "modeled", Assurance.profile.modeled;
        "conservative", Assurance.profile.conservative;
        "unsupported", Assurance.profile.unsupported ]
  in
  let features = list "features" (field root "features") |> nonempty "features" in
  let used_sources = ref [] and used_controls = ref [] and codes = ref [] in
  let source_only = ref 0 and modeled = ref 0 and boundary = ref 0 in
  let matrices = Hashtbl.create 11 in
  List.iter (fun value ->
    let entry = object_ "feature"
        [ "code"; "class"; "rule"; "sources"; "lowering"; "approximation";
          "regressions"; "evidence"; "probes"; "controls"; "gaps" ] value in
    let code = string "feature.code" (field entry "code") in
    codes := code :: !codes;
    let class_ = one_of code [ "modeled"; "conservative"; "unsupported" ] (field entry "class") in
    (match List.assoc_opt code expected with
     | None -> reject code "obsolete or unknown profile feature"
     | Some expected when expected <> class_ -> reject code "profile class mismatch"
     | Some _ -> ());
    ignore (string (code ^ ".rule") (field entry "rule"));
    let references where catalogue used value =
      let refs = strings where value in
      List.iter (fun reference ->
        if not (List.mem_assoc reference catalogue) then reject where ("unknown reference " ^ reference)) refs;
      used := refs @ !used;
      refs
    in
    ignore (references (code ^ ".sources") sources used_sources (field entry "sources")
            |> nonempty (code ^ ".sources"));
    let owners = strings (code ^ ".lowering") (field entry "lowering") |> nonempty (code ^ ".lowering") in
    List.iter (fun path ->
      ignore (local_file read code path);
      if not (String.ends_with ~suffix:".ml" path)
         || not (String.starts_with ~prefix:"connectors/kong/" path
                 || String.starts_with ~prefix:"core/" path)
      then reject code "lowering owner must be a core/ or connectors/kong/ implementation") owners;
    let approximation = one_of code [ "exact"; "may-must"; "reject" ] (field entry "approximation") in
    if (class_ = "conservative" && approximation <> "may-must")
       || (class_ = "unsupported" && approximation <> "reject")
       || (class_ = "modeled" && approximation = "reject") then
      reject code "approximation declaration contradicts profile class";
    let regressions = strings (code ^ ".regressions") (field entry "regressions")
                      |> nonempty (code ^ ".regressions") in
    List.iter (fun path ->
      ignore (local_file read code path);
      if not (String.starts_with ~prefix:"test/" path)
         || not (String.ends_with ~suffix:".ml" path || String.ends_with ~suffix:".sh" path)
      then reject code "regression must reference a test implementation") regressions;
    ignore (references (code ^ ".controls") controls used_controls (field entry "controls"));
    ignore (strings (code ^ ".gaps") (field entry "gaps") |> nonempty (code ^ ".gaps"));
    let evidence = one_of code [ "source-only"; "modeled-samples"; "boundary-samples" ] (field entry "evidence") in
    let probes = list (code ^ ".probes") (field entry "probes") in
    if (evidence = "source-only") <> (probes = []) then
      reject code "source-only must have no probes; sample claims require probes";
    if (class_ = "unsupported" && evidence = "modeled-samples")
       || (class_ <> "unsupported" && evidence = "boundary-samples") then
      reject code "unsupported boundaries are not modeled target agreement";
    let identities = ref [] in
    List.iter (fun value ->
      let probe = object_ code [ "matrix"; "name"; "class"; "flavors" ] value in
      let matrix = string code (field probe "matrix") and name = string code (field probe "name") in
      let declared_class = one_of code [ "exact"; "conservative"; "unsupported" ] (field probe "class") in
      if (evidence = "boundary-samples") <> (declared_class = "unsupported") then
        reject code "unsupported probes cannot count as modeled agreement";
      let flavors = strings code (field probe "flavors") |> nonempty code in
      List.iter (fun flavor -> if not (List.mem flavor routers) then reject code "invalid probe router") flavors;
      let rows = match Hashtbl.find_opt matrices matrix with
        | Some rows -> rows
        | None -> let rows = matrix_probes read matrix in Hashtbl.add matrices matrix rows; rows
      in
      List.iter (fun flavor ->
        identities := (matrix ^ ":" ^ name ^ ":" ^ flavor) :: !identities;
        match List.find_opt (fun row -> row.name = name && row.flavor = flavor) rows with
        | None -> reject code ("missing probe or router " ^ matrix ^ "/" ^ name ^ "/" ^ flavor)
        | Some row when row.model_class <> declared_class -> reject code "probe model class mismatch"
        | Some _ -> ()) flavors) probes;
    ignore (unique (code ^ ".probes") !identities);
    (match evidence with
     | "source-only" -> incr source_only
     | "modeled-samples" -> incr modeled
     | _ -> incr boundary)) features;
  ignore (unique "features" !codes);
  if List.sort String.compare !codes <> List.sort String.compare (List.map fst expected) then
    reject "features" "profile feature coverage is incomplete";
  List.iter (fun (name, _) -> if not (List.mem name !used_sources) then reject "sources" ("unused source " ^ name)) sources;
  List.iter (fun (name, _) -> if not (List.mem name !used_controls) then reject "controls" ("unused control " ^ name)) controls;
  { features = List.length features; source_only = !source_only;
    modeled = !modeled; boundary = !boundary }

let parse source =
  (* The YAML binding exposes NUL-terminated scalar strings. A decoded NUL
     must not shorten an identity or reference before validation. This internal
     inventory needs no escape syntax: reject every raw backslash and NUL,
     including comments, and use literal UTF-8 / YAML single quoting instead. *)
  if String.contains source '\\' || String.contains source '\000' then
    reject "inventory" "backslash characters and literal NUL are unsupported";
  match Parse.yaml_value ~where:"semantic inventory" source with
  | Ok value -> value
  | Error error -> raise (Invalid_inventory error)

(* Controls below corrupt the registry or its referenced inputs in memory;
   they do not modify source files or bless changed target expectations. *)
let set name value = function
  | `O fields -> `O ((name, value) :: List.remove_assoc name fields)
  | _ -> failwith "mutation expected object"

let get name = function `O fields -> List.assoc name fields | _ -> failwith "mutation expected object"
let update name f value = set name (f (get name value)) value
let change_feature code f = update "features" (function
  | `A entries -> `A (List.map (fun entry -> if get "code" entry = `String code then f entry else entry) entries)
  | _ -> failwith "mutation expected features")

let change_first_probe f = update "probes" (function
  | `A (head :: rest) -> `A (f head :: rest)
  | _ -> failwith "mutation expected probe")

let negative_controls read baseline =
  let count = ref 0 in
  let rejects ?(read = read) label value =
    match validate read value with
    | _ -> failwith ("inventory mutation survived: " ^ label)
    | exception Invalid_inventory _ -> incr count
  in
  let feature = change_feature "literal-path-prefix" in
  List.iter (fun (label, mutate) -> rejects label (mutate baseline))
    [ "unknown root field", set "approved" (`Bool true);
      "unsupported schema", set "schema_version" (`Float 2.);
      "wrong profile", set "profile" (`String "kong-traditional-http-v10");
      "floating target revision", update "target" (set "revision" (`String "main"));
      "wrong target version", update "target" (set "version" (`String "3.10"));
      "missing router", update "target" (set "routers" (`A [ `String "traditional" ]));
      "missing feature", update "features" (function `A (_ :: tail) -> `A tail | value -> value);
      "duplicate feature", update "features" (function `A (head :: tail) -> `A (head :: head :: tail) | value -> value);
      "obsolete feature", feature (set "code" (`String "removed-feature"));
      "wrong feature class", feature (set "class" (`String "conservative"));
      "false complete claim", feature (set "evidence" (`String "complete"));
      "missing semantic rule", feature (set "rule" (`String ""));
      "missing source", feature (set "sources" (`A []));
      "unknown source", feature (set "sources" (`A [ `String "nonexistent" ]));
      "missing owner", feature (set "lowering" (`A [ `String "core/nonexistent.ml" ]));
      "owner traversal", feature (set "lowering" (`A [ `String "core/../core/ir.ml" ]));
      "missing regression", feature (set "regressions" (`A [ `String "test/nonexistent.ml" ]));
      "non-test regression", feature (set "regressions" (`A [ `String "core/ir.ml" ]));
      "empty gaps", feature (set "gaps" (`A []));
      "unknown control", feature (set "controls" (`A [ `String "nonexistent" ]));
      "source-only with probes", feature (set "evidence" (`String "source-only"));
      "samples without probes", feature (set "probes" (`A []));
      "missing matrix", feature (change_first_probe (set "matrix" (`String "nonexistent")));
      "missing probe", feature (change_first_probe (set "name" (`String "nonexistent")));
      "duplicate probe", feature (update "probes" (function `A (head :: rest) -> `A (head :: head :: rest) | value -> value));
      "false probe class", feature (change_first_probe (set "class" (`String "conservative")));
      "invalid router", feature (change_first_probe (set "flavors" (`A [ `String "expressions" ])));
      "unsupported counts as agreement", feature (change_first_probe (fun probe ->
        probe |> set "matrix" (`String "boundaries") |> set "name" (`String "unicode-one")
        |> set "class" (`String "unsupported")));
      "modeled feature claims boundary evidence", feature (set "evidence" (`String "boundary-samples"));
      "unsupported feature claims agreement", change_feature "unsupported-path-regex" (set "evidence" (`String "modeled-samples"));
      "conservative declared exact", change_feature "regex-match-runtime" (set "approximation" (`String "exact"));
      "unsupported declared modeled", change_feature "unsupported-path-regex" (set "approximation" (`String "may-must"));
      "floating source URL", update "sources" (set "traditional" (`String "https://github.com/Kong/kong/blob/master/kong/router/traditional.lua"));
      "source path traversal", update "sources" (set "traditional" (`String (source_prefix ^ "kong/../README.md")));
      "control anchor missing", update "controls" (update "incomplete-suppression" (set "anchor" (`String "missing-control-anchor")));
      "duplicate field", (function `O fields -> `O (("profile", `String Assurance.profile.id) :: fields) | value -> value) ];
  let paths = "bench/kong/conformance/paths-probes.tsv" in
  let rows = read paths |> String.split_on_char '\n' in
  let probe_row = List.find (fun row -> String.starts_with ~prefix:"literal-long|" row) rows in
  let override replacement path = if path = paths then replacement else read path in
  rejects ~read:(override (String.concat "\n" (probe_row :: rows)))
    "duplicate matrix identity" baseline;
  rejects ~read:(override "# empty fixture\n") "empty matrix" baseline;
  rejects ~read:(override (probe_row ^ "|unexpected\n")) "malformed matrix row" baseline;
  let termination = "bench/kong/conformance/termination-probes.tsv" in
  let query_rows = read termination |> String.split_on_char '\n' in
  let query_row = List.find (fun row ->
      String.starts_with ~prefix:"route-query-trigger-present|" row) query_rows in
  let query_fields = String.split_on_char '|' query_row |> List.mapi
      (fun i value -> if i = 15 then "" else value) |> String.concat "|" in
  List.iter (fun query ->
    let replacement = List.map (fun row ->
        if row = query_row then query_fields ^ query else row) query_rows
        |> String.concat "\n" in
    let override path = if path = termination then replacement else read path in
    rejects ~read:override ("invalid query " ^ query) baseline)
    [ "x-stop=yes#fragment"; "x-stop=%79es"; "x-stop=yes extra";
      "x-stop=yes|extra"; "x-stop"; "x-stop=yes&"; "x-stop=[a]";
      "x-stop=yes?again=yes" ];
  let one_flavor = String.split_on_char '|' probe_row
    |> List.mapi (fun i value -> if i = 13 then "traditional" else value)
    |> String.concat "|" in
  let changed = List.map (fun row -> if row = probe_row then one_flavor else row) rows |> String.concat "\n" in
  rejects ~read:(override changed) "claim missing compatible observation" baseline;
  let no_file path = if path = "core/ir.ml" then raise (Sys_error "absent") else read path in
  rejects ~read:no_file "referenced local file removed" baseline;
  (match parse "schema_version: 1\nschema_version: 1\n" with
   | _ -> failwith "duplicate YAML field accepted"
   | exception Invalid_inventory _ -> incr count);
  List.iter (fun (label, source) ->
    match parse source with
    | _ -> failwith ("inventory parser accepted " ^ label)
    | exception Invalid_inventory _ -> incr count)
    [ "literal NUL", "profile: \"" ^ Assurance.profile.id ^ "\000junk\"\n";
      "short NUL escape", "profile: \"" ^ Assurance.profile.id ^ "\\0junk\"\n";
      "hex NUL escape", "profile: \"" ^ Assurance.profile.id ^ "\\x00junk\"\n";
      "Unicode NUL escape", "profile: \"" ^ Assurance.profile.id ^ "\\u0000junk\"\n";
      "long Unicode NUL escape", "profile: \"" ^ Assurance.profile.id ^ "\\U00000000junk\"\n";
      "escaped reference NUL", "sources: [\"traditional\\u0000junk\"]\n";
      "non-NUL backslash escape", "text: \"line\\nbreak\"\n";
      "backslash in comment", "# no \\ escape syntax anywhere\ntext: literal\n" ];
  List.iter (fun (source, expected) ->
    if parse source <> `O [ "text", `String expected ] then
      failwith "inventory parser changed a permitted literal")
    [ "text: literal/path-01\n", "literal/path-01";
      "text: 'reader''s \"quoted\" note'\n", "reader's \"quoted\" note";
      "text: 'référence Ω'\n", "référence Ω" ];
  !count

let () =
  if Array.length Sys.argv <> 3 then
    failwith "usage: semantic_acceptance_t REPOSITORY_ROOT INVENTORY";
  let read path = read_file (Filename.concat Sys.argv.(1) path) in
  let inventory = read_file Sys.argv.(2) |> parse in
  let stats = validate read inventory in
  let controls = negative_controls read inventory in
  Printf.printf
    "Semantic inventory integrity: %d profile features; %d source-only, %d modeled-sample, %d boundary-sample entries; %d rejected corruption controls.\n"
    stats.features stats.source_only stats.modeled stats.boundary controls;
  print_endline "Reference integrity only: finite samples and citations are not complete semantic coverage."
