open Soundcheck_core

let ok = function Ok value -> value | Error reason -> failwith reason

let read_file path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
      really_input_string channel (in_channel_length channel))

let write_file path contents =
  let channel = open_out_bin path in
  output_string channel contents;
  close_out channel

let rec cleanup path =
  match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR ->
    Sys.readdir path |> Array.iter (fun name -> cleanup (Filename.concat path name));
    Unix.rmdir path
  | _ -> Unix.unlink path

let temporary_directory () =
  let path = Filename.temp_file "soundcheck-evidence-" "" in
  Unix.unlink path;
  Unix.mkdir path 0o700;
  path

let canonical =
  {|{"schema_version":1,"kind":"authenticated-access","scope":{"path_prefix":"/admin","method":"GET","host":null}}|}

let profile : Evidence.profile =
  { id = "test-profile"; json = {|{"schema_version":1,"id":"test-profile"}|} }

let provenance : Evidence.provenance =
  { executable_sha256 = String.make 64 'f';
    ocaml_version = "test-ocaml";
    z3_version = Ok "Z3 version test" }

let report : Report.t =
  { result = Unknown "timeout\001";
    property_name = "authenticated-access";
    property_description = "Admin access";
    assurance = Some { profile = profile.id; status = Within_profile; findings = [] };
    clause = None;
    frozen_spec =
      Some { schema_version = 1; kind = "authenticated-access"; canonical } }

let model : Solve.model =
  { path = "/admin"; method_ = "GET"; is_anon = true; src_ip = 0x0a000001l;
    host = "admin.example"; scheme = "https"; sni = "admin.example";
    headers = [ ("x-z", "last"); ("x-a", "first") ] }

let entry id phase clauses smtlib execution : Contract_verify.trace_entry =
  { obligation = { id; phase; clauses; smtlib }; execution }

let trace =
  Contract_verify.
    [ entry "inhabitance-01-denied" Inhabitance [ "denied" ]
        "(assert true)\n(check-sat)\n" (Executed (Solve.Violated model));
      entry "inhabitance-02-allowed" Inhabitance [ "allowed" ]
        "(assert true)\n(check-sat)\n"
        (Executed (Solve.Violated { model with is_anon = false }));
      entry "consistency-01-denied-allowed" Consistency [ "denied"; "allowed" ]
        "(assert false)\n(check-sat)\n" (Executed Solve.Proved);
      entry "clause-01-denied" Clause [ "denied" ]
        "; solver timeout\n(check-sat)\n" (Executed (Solve.Unknown "timeout\001"));
      entry "clause-02-allowed" Clause [ "allowed" ]
        "; unexecuted\n(check-sat)\n" Not_executed ]

let create ?(report = report) ?(profile = profile) ?(provenance = provenance)
    ?(trace = Some trace) () =
  Evidence.create ~config:"abc" ~profile ~provenance ~report ~trace

let expect_error label result =
  match result with Error _ -> () | Ok _ -> failwith (label ^ " was accepted")

let contains text fragment =
  let rec search index =
    index + String.length fragment <= String.length text
    && (String.sub text index (String.length fragment) = fragment || search (index + 1))
  in
  search 0

let manifest bundle = List.assoc "manifest.json" (Evidence.files bundle)

let () =
  if Array.length Sys.argv <> 2 then failwith "expected evidence golden directory";
  let bundle = ok (create ()) in
  let files = Evidence.files bundle in
  let expected_paths =
    [ "contract.json"; "assurance-profile.json"; "report.json";
      "queries/inhabitance-01-denied.smt2";
      "queries/inhabitance-02-allowed.smt2";
      "queries/consistency-01-denied-allowed.smt2";
      "queries/clause-01-denied.smt2"; "queries/clause-02-allowed.smt2";
      "manifest.json" ]
  in
  if List.map fst files <> expected_paths then failwith "evidence file order changed";
  List.iter
    (fun (path, contents) ->
      let expected = read_file (Filename.concat Sys.argv.(1) path) in
      if contents <> expected then failwith ("evidence golden changed: " ^ path))
    files;
  if files <> Evidence.files (ok (create ())) then
    failwith "identical evidence input changed bundle contents";
  expect_error "unfrozen report" (create ~report:{ report with frozen_spec = None } ());
  expect_error "missing assurance" (create ~report:{ report with assurance = None } ());
  expect_error "different profile" (create ~profile:{ profile with id = "different" } ());
  expect_error "missing obligation plan" (create ~trace:None ());
  let first = List.hd trace in
  expect_error "duplicate obligation identity" (create ~trace:(Some [ first; first ]) ());
  let unsafe = { first with obligation = { first.obligation with id = "../escape" } } in
  expect_error "unsafe obligation identity" (create ~trace:(Some [ unsafe ]) ());
  let unsupported =
    { report with result = Unknown "unsupported fragment";
      assurance = Some { profile = profile.id; status = Unsupported; findings = [] } }
  in
  let unavailable = manifest (ok (create ~report:unsupported ~trace:None ())) in
  if not (contains unavailable {|"obligation_plan":{"status":"unavailable","reason":"unsupported fragment"}|})
     || not (contains unavailable {|"obligations":[]|})
  then failwith "unsupported input silently acquired a complete evidence plan";
  let no_version =
    manifest (ok (create ~provenance:{ provenance with z3_version = Error "unavailable" } ()))
  in
  if not (contains no_version {|"version":null,"version_error":"unavailable"|}) then
    failwith "missing solver version was not recorded";
  List.iter
    (fun outcome ->
      let changed = ok (create ~report:{ report with result = outcome } ()) in
      if List.assoc "report.json" (Evidence.files changed)
         <> Report.to_json { report with result = outcome } ^ "\n"
      then failwith "evidence changed the verdict report")
    [ Report.Proved; Report.Vacuous; Report.Inconsistent "overlap"; report.result ];
  let directory = temporary_directory () in
  Fun.protect ~finally:(fun () -> cleanup directory) (fun () ->
      let target = Filename.concat directory "bundle" in
      ok (Evidence.write ~directory:target bundle);
      List.iter
        (fun (path, contents) ->
          if read_file (Filename.concat target path) <> contents then
            failwith ("evidence write changed " ^ path))
        files;
      expect_error "existing directory" (Evidence.write ~directory:target bundle);
      if read_file (Filename.concat target "manifest.json") <> manifest bundle then
        failwith "existing manifest was overwritten";
      let occupied_file = Filename.concat directory "occupied" in
      write_file occupied_file "preserve me";
      expect_error "existing file" (Evidence.write ~directory:occupied_file bundle);
      let link = Filename.concat directory "link" in
      Unix.symlink occupied_file link;
      expect_error "existing symlink" (Evidence.write ~directory:link bundle);
      let dangling = Filename.concat directory "dangling" in
      Unix.symlink (Filename.concat directory "absent") dangling;
      expect_error "dangling symlink" (Evidence.write ~directory:dangling bundle);
      if read_file occupied_file <> "preserve me" then failwith "existing file was overwritten";
      expect_error "missing parent"
        (Evidence.write ~directory:(Filename.concat directory "missing/bundle") bundle);
      let too_long =
        { first with obligation = { first.obligation with id = String.make 1000 'a' } }
      in
      let unwritable = ok (create ~trace:(Some [ too_long ]) ()) in
      let incomplete = Filename.concat directory "incomplete" in
      expect_error "payload write failure" (Evidence.write ~directory:incomplete unwritable);
      if not (Sys.file_exists (Filename.concat incomplete "report.json"))
         || Sys.file_exists (Filename.concat incomplete "manifest.json")
      then failwith "failed payload write published a completion manifest")
