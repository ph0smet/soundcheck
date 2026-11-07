open Soundcheck_core
open Soundcheck_kong

let checks = ref 0
let check name condition =
  incr checks;
  if not condition then failwith ("pilot check failed: " ^ name)
let ok = function Ok value -> value | Error _ -> failwith "unexpected input failure"
let contains text fragment =
  let rec search index =
    index + String.length fragment <= String.length text
    && (String.sub text index (String.length fragment) = fragment || search (index + 1))
  in search 0
let case_json ?(id = "demo") ?(config = "config.yaml") ?(contract = "contract.yaml")
    ?(provenance = "synthetic") () =
  Printf.sprintf {|{"id":%S,"config":%S,"contract":%S,"provenance":%S}|}
    id config contract provenance
let manifest cases = {|{"format_version":1,"cases":[|} ^ String.concat "," cases ^ "]}"
let secret = "PRIVATE_SENTINEL_8efb4d"
let contract =
  "schema_version: 1\nkind: authenticated-access\nscope:\n  path_prefix: /" ^ secret
  ^ "\n  method: GET\n  host: " ^ secret ^ ".example\n"
let witness : Report.counterexample =
  { principal = secret; action = secret; path = secret; route = Some secret;
    service = Some secret; shadowed_route = Some secret; shadowed_service = Some secret;
    host = secret; scheme = secret; sni = secret; source_ip = 0l;
    headers = [ secret, secret ]; object_request = None;
    identity_groups = None; granting_rules = []; note = secret }
let report ?(status = Report.Within_profile) ?(codes = []) result : Report.t =
  { result; property_name = "authenticated-access"; property_description = secret;
    assurance = Some { profile = Assurance.profile.id; status;
      findings = List.map (fun code -> { Report.code; service = Some secret;
        route = Some secret; detail = secret }) codes };
    clause = Some { name = secret; description = secret; kind = Report.Must_deny };
    frozen_spec = None }
let field key = function
  | `O fields -> (match List.assoc_opt key fields with Some value -> value | None -> failwith key)
  | _ -> failwith "object expected"
let parse_json source = match Yaml.of_string source with Ok value -> value | Error _ -> failwith "bad JSON"

let () =
  check "valid manifest" (Result.is_ok (Pilot.parse_manifest (manifest [ case_json () ])));
  List.iter (fun provenance -> check ("provenance " ^ provenance)
    (Result.is_ok (Pilot.parse_manifest (manifest [ case_json ~provenance () ]))))
    [ "synthetic"; "upstream-example"; "authorized-deployment" ];
  check "literal spaces" (Result.is_ok
    (Pilot.parse_manifest (manifest [ case_json ~config:"folder with spaces/config.yaml" () ])));
  let invalid =
    [ ""; "[]"; "{}"; "format_version: 1\ncases: []\n";
      {|{"format_version":2,"cases":[|} ^ case_json () ^ "]}";
      {|{"format_version":"1","cases":[|} ^ case_json () ^ "]}";
      {|{"format_version":1,"cases":[|} ^ case_json () ^ {|],"extra":1}|};
      {|{"format_version":1,"format_version":1,"cases":[|} ^ case_json () ^ "]}";
      manifest [ {|{"id":"demo","id":"other","config":"a","contract":"b","provenance":"synthetic"}|} ];
      manifest [ {|{"id":"demo","config":"a","contract":"b"}|} ];
      manifest [ {|{"id":"demo","config":"a","contract":"b","provenance":"synthetic","extra":1}|} ];
      manifest [ {|{"id":"demo","config":null,"contract":"b","provenance":"synthetic"}|} ];
      manifest [ case_json (); case_json () ];
      manifest [ case_json ~id:"" () ]; manifest [ case_json ~id:"has spaces" () ];
      manifest [ case_json ~id:(String.make 65 'a') () ];
      manifest [ case_json ~provenance:"production" () ];
      manifest [ case_json ~config:"../outside.yaml" () ];
      manifest [ case_json ~config:"nested/../outside.yaml" () ];
      manifest [ case_json ~config:"/absolute.yaml" () ];
      manifest [ case_json ~config:"./config.yaml" () ];
      manifest [ case_json ~config:"folder//config.yaml" () ];
      manifest [ case_json ~config:"folder/" () ];
      manifest [ case_json ~config:"" () ];
      manifest [ case_json ~contract:"../contract.yaml" () ];
      manifest [ {|{"id":"demo","config":"a\\b","contract":"b","provenance":"synthetic"}|} ];
      manifest [ {|{"id":"demo","config":"a\u0000b","contract":"b","provenance":"synthetic"}|} ];
      manifest [ {|{"id":"demo","config":"a\nb","contract":"b","provenance":"synthetic"}|} ];
      manifest [ case_json () ] ^ "\n---\nother: document\n";
      "format_version: !!int 1\ncases: []\n";
      "format_version: 1\ncases: [*missing]\n";
      "format_version: 1\ncases: [{id: demo, config: &p config.yaml, contract: *p, provenance: synthetic}]\n";
      "format_version: 1\ncases: [{<<: {id: demo}, config: a, contract: b, provenance: synthetic}]\n" ]
  in
  List.iteri (fun index source -> check (Printf.sprintf "invalid manifest %d" index)
    (Result.is_error (Pilot.parse_manifest source))) invalid;
  let cases = [ "proved"; "violated"; "vacuous"; "inconsistent"; "unknown";
    "unsupported"; "missing"; "verification"; "exception"; "mismatch";
    "bad-contract"; "missing-contract" ] in
  let inputs = ok (Pilot.parse_manifest (manifest (List.map (fun id ->
    case_json ~id ~config:(id ^ secret ^ ".yaml")
      ~contract:(if id = "bad-contract" then "bad.yaml"
                 else if id = "missing-contract" then "absent.yaml"
                 else secret ^ "-contract.yaml") ()) cases))) in
  let reads = Hashtbl.create 20 and calls = ref [] in
  let read path =
    Hashtbl.replace reads path (1 + Option.value ~default:0 (Hashtbl.find_opt reads path));
    if path = secret ^ "-contract.yaml" then Ok contract
    else if path = "bad.yaml" then Ok ("unexpected: " ^ secret)
    else if path = "absent.yaml" || path = "missing" ^ secret ^ ".yaml" then Error ()
    else Ok path
  in
  let verify property bytes =
    check "all contracts frozen before first verification"
      (Hashtbl.mem reads "bad.yaml" && Hashtbl.mem reads "absent.yaml");
    check "explicit frozen scope retained"
      (match property with Verify.Authenticated_access scope ->
        scope.path_prefix = "/" ^ secret && scope.host = Some (String.lowercase_ascii secret ^ ".example")
       | _ -> false);
    calls := bytes :: !calls;
    if String.starts_with ~prefix:"proved" bytes then Ok (report Report.Proved)
    else if String.starts_with ~prefix:"violated" bytes then
      Ok (report ~status:Report.Conservative
        ~codes:[ "auth-anonymous-fallback"; "shared-route-order"; "auth-anonymous-fallback" ]
        (Report.Violated witness))
    else if String.starts_with ~prefix:"vacuous" bytes then Ok (report Report.Vacuous)
    else if String.starts_with ~prefix:"inconsistent" bytes then Ok (report (Report.Inconsistent secret))
    else if String.starts_with ~prefix:"unknown" bytes then Ok (report (Report.Unknown secret))
    else if String.starts_with ~prefix:"unsupported" bytes then
      Ok (report ~status:Report.Unsupported ~codes:[ "unrecognized-plugin" ] (Report.Unknown secret))
    else if String.starts_with ~prefix:"verification" bytes then Error secret
    else if String.starts_with ~prefix:"exception" bytes then failwith secret
    else Ok (report ~codes:[ secret ] Report.Proved)
  in
  let clock = ref 0. in
  let now () = clock := !clock +. 0.25; !clock in
  let rows = Pilot.run ~read ~verify ~now ~root:"unused" inputs in
  check "all scheduled cases retained" (List.length rows = 12);
  check "input order preserved" (List.map (fun (row : Pilot.row) -> row.id) rows = cases);
  check "shared contract read once" (Hashtbl.find reads (secret ^ "-contract.yaml") = 1);
  check "every explicit read at most once" (Hashtbl.fold (fun _ n valid -> valid && n = 1) reads true);
  check "invalid contracts skip config IO" (not (Hashtbl.mem reads ("bad-contract" ^ secret ^ ".yaml")));
  check "verification sequential and complete" (List.rev !calls =
    List.map (fun id -> id ^ secret ^ ".yaml")
      [ "proved"; "violated"; "vacuous"; "inconsistent"; "unknown"; "unsupported";
        "verification"; "exception"; "mismatch" ]);
  let row name = List.find (fun (row : Pilot.row) -> row.id = name) rows in
  let canonical = Contract_spec.canonical_json (ok (Contract_spec.parse_string contract)) in
  check "canonical contract digest" ((row "proved").contract_sha256 = Some (Sha256.string canonical));
  check "checked bytes hashed" ((row "proved").config_sha256 = Some (Sha256.string ("proved" ^ secret ^ ".yaml")));
  check "exception retains checked input digest" ((row "exception").config_sha256 = Some (Sha256.string ("exception" ^ secret ^ ".yaml")));
  check "sorted unique finding codes" ((row "violated").finding_codes =
    [ "auth-anonymous-fallback"; "shared-route-order" ]);
  check "unsupported uncertainty" ((row "unsupported").uncertainty = Some "unsupported");
  check "unknown reason not reinterpreted" ((row "unknown").uncertainty = Some "unresolved");
  List.iter (fun (name, failure) -> check ("failure category " ^ name) ((row name).failure = Some failure))
    [ "bad-contract", Pilot.Contract_invalid; "missing-contract", Pilot.Contract_read_error;
      "missing", Pilot.Config_read_error; "verification", Pilot.Verification_error;
      "exception", Pilot.Unexpected_error; "mismatch", Pilot.Report_mismatch ];
  check "deterministic clock" (List.for_all (fun (row : Pilot.row) -> row.elapsed_seconds = 0.25) rows);
  let summary = Pilot.to_json rows in
  check "privacy projection" (not (contains summary secret) && not (contains summary (String.lowercase_ascii secret)));
  check "deterministic serialization" (summary = Pilot.to_json rows);
  let json = parse_json summary in
  check "scheduled denominator" (field "scheduled" json = `Float 12.);
  check "processed denominator" (field "processed" json = `Float 12.);
  let counts = field "counts" json in
  List.iter (fun (name, expected) -> check ("count " ^ name) (field name counts = `Float expected))
    [ "proved", 1.; "violated", 1.; "vacuous", 1.; "inconsistent", 1.; "unknown", 2.; "errors", 6. ];
  check "mixed errors nonzero" (Pilot.exit_code rows = 1);
  check "empty not success" (Pilot.exit_code [] = 1);
  check "only proved is zero" (Pilot.exit_code [ row "proved" ] = 0);
  List.iter (fun name -> check ("nonproof " ^ name) (Pilot.exit_code [ row "proved"; row name ] = 3))
    [ "violated"; "vacuous"; "inconsistent"; "unknown"; "unsupported" ];
  let bad_report = Pilot.run ~read
      ~verify:(fun _ _ -> Ok (report ~status:Report.Unsupported Report.Proved))
      ~root:"unused" [ List.hd inputs ] in
  check "unsupported proof rejected" ((List.hd bad_report).failure = Some Pilot.Report_mismatch);
  let bad_profile = Pilot.run ~read
      ~verify:(fun _ _ -> Ok { (report Report.Proved) with assurance = None })
      ~root:"unused" [ List.hd inputs ] in
  check "absent profile rejected" ((List.hd bad_profile).failure = Some Pilot.Report_mismatch);
  let wrong_identity = Pilot.run ~read
      ~verify:(fun _ _ -> Ok { (report Report.Proved) with frozen_spec =
        Some { schema_version = 1; kind = "authenticated-access"; canonical = secret } })
      ~root:"unused" [ List.hd inputs ] in
  check "substituted identity rejected" ((List.hd wrong_identity).failure = Some Pilot.Report_mismatch);
  let wrong_property = Pilot.run ~read
      ~verify:(fun _ _ -> Ok { (report Report.Proved) with property_name = "other-property" })
      ~root:"unused" [ List.hd inputs ] in
  check "substituted property rejected" ((List.hd wrong_property).failure = Some Pilot.Report_mismatch);
  let root = Filename.temp_file "soundcheck-pilot-files-" "" in
  Unix.unlink root; Unix.mkdir root 0o700;
  let write name bytes =
    let channel = open_out_bin (Filename.concat root name) in
    Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () -> output_string channel bytes)
  in
  let rec remove path =
    if (Unix.lstat path).Unix.st_kind = Unix.S_DIR then begin
      Array.iter (fun name -> remove (Filename.concat path name)) (Sys.readdir path);
      Unix.rmdir path
    end else Unix.unlink path
  in
  Fun.protect ~finally:(fun () -> remove root) (fun () ->
    write "regular file.yaml" "one\000two\n";
    Unix.mkdir (Filename.concat root "nested") 0o700;
    write "nested/config.yaml" "nested";
    Unix.symlink "regular file.yaml" (Filename.concat root "file-link.yaml");
    Unix.symlink "nested" (Filename.concat root "dir-link");
    Unix.mkfifo (Filename.concat root "fifo") 0o600;
    check "binary exact read" (Pilot.read_regular ~root "regular file.yaml" = Ok "one\000two\n");
    check "nested explicit read" (Pilot.read_regular ~root "nested/config.yaml" = Ok "nested");
    List.iter (fun path -> check ("nonregular/path rejected " ^ path)
      (Pilot.read_regular ~root path = Error ()))
      [ "file-link.yaml"; "dir-link/config.yaml"; "fifo"; "nested"; "missing";
        "../outside"; "/absolute"; "nested/../regular file.yaml" ]);
  Printf.printf "All %d experimental pilot unit checks passed.\n" !checks
