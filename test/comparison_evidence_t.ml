open Soundcheck_core

let checks = ref 0
let check label condition = incr checks; if not condition then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let error label = function Error _ -> incr checks | Ok _ -> failwith (label ^ " accepted")

let parsed value = match Yaml.of_string value with
  | Ok value -> value | Error (`Msg reason) -> failwith reason
let field key = function
  | `O fields -> (match List.assoc_opt key fields with Some value -> value | None -> failwith ("missing " ^ key))
  | _ -> failwith ("not an object: " ^ key)
let string = function `String value -> value | _ -> failwith "not a string"
let array = function `A values -> values | _ -> failwith "not an array"
let number = function `Float value -> int_of_float value | _ -> failwith "not a number"

let canonical = {|{"schema_version":1,"kind":"example-access","identities":["alice"]}|}
let frozen : Report.frozen_spec = {schema_version=1;kind="example-access";canonical}
let profile : Evidence.profile = {id="example-profile";json={|{"id":"example-profile"}|}}
let provenance : Evidence.provenance =
  {executable_sha256=String.make 64 'a';ocaml_version="test-ocaml";z3_version=Ok "Z3 version test"}
let base_report : Report.t =
  {result=Proved;property_name="example-access";property_description="required access";
   assurance=Some {profile=profile.id;status=Within_profile;findings=[]};clause=None;frozen_spec=Some frozen}
let final_report = {base_report with property_name="example-repair";property_description="preserve decisions"}
let model : Solve.model =
  {path="";method_="get";is_anon=false;src_ip=0l;host="";scheme="";sni="";headers=[];
   principal_name=Some "alice";object_request=Some {namespace="team";resource_kind="configmaps";name="settings"}}
let counterexample : Report.counterexample =
  {principal="alice";action="get";path="";route=None;service=None;shadowed_route=None;shadowed_service=None;
   host="";scheme="";sni="";source_ip=0l;headers=[];object_request=model.object_request;
   identity_groups=Some ["team"];granting_rules=[];note="validated modeled difference"}

let entry id phase clauses execution : Contract_verify.trace_entry =
  {obligation={id;phase;clauses;smtlib="; " ^ id ^ "\n(check-sat)\n"};execution}
let candidate = Contract_verify.[
  entry "inhabitance-01-allow" Inhabitance ["allow"] (Executed (Solve.Violated model));
  entry "inhabitance-02-deny" Inhabitance ["deny"] (Executed (Solve.Violated model));
  entry "consistency-01-deny-allow" Consistency ["deny";"allow"] (Executed Solve.Proved);
  entry "clause-01-allow" Clause ["allow"] (Executed Solve.Proved);
  entry "clause-02-deny" Clause ["deny"] (Executed Solve.Proved)]
let preservation : Evidence.preservation_trace =
  {id="preservation-outside-scope";smtlib="; exact preservation query\n(check-sat)\n";
   execution=Contract_verify.Executed Solve.Proved}
let trace : Evidence.comparison_trace = {candidate;preservation}
let before = "before snapshot\n"
let after = "after snapshot \xc3\xa9\n"

let create ?(before=before) ?(after=after) ?(report=final_report)
    ?(candidate_report=Some base_report) ?(trace=Some trace) ?(profile=profile)
    ?(provenance=provenance) () =
  Evidence.create_comparison ~before ~after ~profile ~provenance ~report ~candidate_report ~trace

let manifest bundle = Evidence.files bundle |> List.assoc "manifest.json" |> parsed
let obligation_rows bundle = manifest bundle |> field "obligations" |> array
let preservation_row bundle = List.rev (obligation_rows bundle) |> List.hd
let has_path path bundle = List.mem_assoc path (Evidence.files bundle)

let failed_candidate index answer =
  List.mapi (fun i (row : Contract_verify.trace_entry) ->
      if i < index then row
      else {row with execution=if i=index then Contract_verify.Executed answer else Not_executed}) candidate

let failed_trace candidate : Evidence.comparison_trace =
  {candidate;preservation={preservation with execution=Not_executed}}

let binding_checks () =
  let bundle = create () |> ok in
  let m = manifest bundle in
  check "comparison version is separate" (Evidence.schema_version=2 && Evidence.comparison_schema_version=3);
  check "manifest version" (number (field "schema_version" m)=3);
  check "operation" (string (field "operation" m)="repair_comparison");
  List.iter (fun (name,source) ->
      let input = m |> field "inputs" |> field name in
      check (name ^ " digest") (string (field "sha256" input)=Sha256.string source);
      check (name ^ " byte length") (number (field "size_bytes" input)=String.length source))
    ["before",before;"after",after];
  let artifact value =
    let path = field "path" value |> string in
    let contents = List.assoc path (Evidence.files bundle) in
    check ("artifact digest " ^ path) (string (field "sha256" value)=Sha256.string contents)
  in
  artifact (field "contract" m);
  artifact (m |> field "assurance_profile" |> field "artifact");
  artifact (field "candidate_report" m);
  artifact (field "report" m);
  List.iter (fun row -> artifact (field "query" row)) (obligation_rows bundle);
  check "all obligations retained" (List.length (obligation_rows bundle)=List.length candidate+1);
  check "preservation is a distinct phase" (string (field "phase" (preservation_row bundle))="preservation");
  check "candidate report exact" (List.assoc "candidate-report.json" (Evidence.files bundle)=Report.to_json base_report ^ "\n");
  check "final report exact" (List.assoc "report.json" (Evidence.files bundle)=Report.to_json final_report ^ "\n");
  check "contract canonical bytes" (List.assoc "contract.json" (Evidence.files bundle)=canonical ^ "\n");
  check "manifest last" (fst (List.hd (List.rev (Evidence.files bundle)))="manifest.json");
  check "input snapshots not copied" (not (List.exists (fun (_,contents) -> contents=before || contents=after) (Evidence.files bundle)));
  check "deterministic bytes" (Evidence.files bundle=Evidence.files (ok (create ())));
  let reversed = create ~before:after ~after:before () |> ok |> manifest in
  check "before and after do not alias"
    (string (reversed |> field "inputs" |> field "before" |> field "sha256")=Sha256.string after);
  let unavailable_version = create ~provenance:{provenance with z3_version=Error "not available"} () |> ok |> manifest in
  check "missing solver version explicit"
    (unavailable_version |> field "solver" |> field "version" = `Null);
  check "solver version reason retained"
    (string (unavailable_version |> field "solver" |> field "version_error")="not available")

let stage_checks () =
  List.iter (fun (label,index,answer,result) ->
      let report = {base_report with result} in
      let trace = failed_trace (failed_candidate index answer) in
      let bundle = create ~report ~candidate_report:(Some report) ~trace:(Some trace) () |> ok in
      check (label ^ " preserves the complete plan") (List.length (obligation_rows bundle)=6);
      let row = preservation_row bundle in
      check (label ^ " leaves preservation unexecuted") (string (field "execution" row)="not_executed");
      check (label ^ " has no preservation verdict") (field "solver_result" row=`Null && field "model" row=`Null);
      check (label ^ " retains preservation query") (has_path "queries/preservation-outside-scope.smt2" bundle);
      error (label ^ " cannot execute preservation")
        (create ~report ~candidate_report:(Some report)
           ~trace:(Some {trace with preservation}) ());
      error (label ^ " cannot become proved")
        (create ~candidate_report:(Some report) ~trace:(Some trace) ()))
    ["vacuous",0,Solve.Proved,Report.Vacuous;
     "inconsistent",2,Solve.Violated model,Report.Inconsistent "overlap";
     "violated",3,Solve.Violated model,Report.Violated counterexample;
     "unknown",3,Solve.Unknown "validated witness rejected",Report.Unknown "validated witness rejected"];
  let differing = {final_report with result=Violated counterexample} in
  let sat_trace = {trace with preservation={preservation with execution=Executed (Solve.Violated model)}} in
  let sat = create ~report:differing ~trace:(Some sat_trace) () |> ok in
  let row = preservation_row sat in
  check "preservation SAT recorded" (string (field "solver_result" row)="sat");
  check "typed witness identity retained" (string (row |> field "model" |> field "principal_name")="alice");
  check "typed witness coordinates retained"
    (string (row |> field "model" |> field "object_request" |> field "namespace")="team");
  let unknown = {final_report with result=Unknown "invalid preservation witness"} in
  let bad_trace = {trace with preservation={preservation with execution=Executed (Solve.Unknown "invalid preservation witness")}} in
  let bad = create ~report:unknown ~trace:(Some bad_trace) () |> ok in
  let row = preservation_row bad in
  check "rejected witness exports unknown" (string (field "solver_result" row)="unknown");
  check "rejected witness exports no raw model" (field "model" row=`Null);
  error "unknown preservation cannot prove" (create ~trace:(Some bad_trace) ());
  error "SAT preservation cannot prove" (create ~trace:(Some sat_trace) ());
  error "UNSAT preservation cannot violate" (create ~report:differing ());
  error "UNSAT preservation cannot be unknown" (create ~report:unknown ());
  error "preservation unknown reason mismatch"
    (create ~report:{unknown with result=Unknown "unrelated reason"} ~trace:(Some bad_trace) ());
  error "proved candidate cannot skip preservation"
    (create ~trace:(Some {trace with preservation={preservation with execution=Not_executed}}) ());
  let candidate_unknown = {base_report with result=Unknown "different candidate reason"} in
  error "candidate unknown reason mismatch"
    (create ~report:candidate_unknown ~candidate_report:(Some candidate_unknown)
       ~trace:(Some (failed_trace (failed_candidate 0 (Solve.Unknown "recorded reason")))) ())

let boundary_checks () =
  let unsupported = {final_report with result=Unknown "unsupported snapshot";
    assurance=Some {profile=profile.id;status=Unsupported;findings=[]}} in
  let bundle = create ~report:unsupported ~trace:None ~candidate_report:None () |> ok in
  let m = manifest bundle in
  check "unsupported plan unavailable" (string (m |> field "obligation_plan" |> field "status")="unavailable");
  check "unsupported reason preserved" (string (m |> field "obligation_plan" |> field "reason")="unsupported snapshot");
  check "unexecuted candidate absent" (field "candidate_report" m=`Null && not (has_path "candidate-report.json" bundle));
  check "unavailable obligations empty" (array (field "obligations" m)=[]);
  error "proved cannot omit plan" (create ~trace:None ~candidate_report:None ());
  error "supported unknown cannot omit plan"
    (create ~report:{final_report with result=Unknown "timeout"} ~trace:None ~candidate_report:None ());
  error "unsupported cannot claim complete plan" (create ~report:unsupported ());
  error "trace requires candidate report" (create ~candidate_report:None ());
  error "candidate report requires trace" (create ~trace:None ());
  error "missing final contract" (create ~report:{final_report with frozen_spec=None} ());
  error "missing final profile" (create ~report:{final_report with assurance=None} ());
  error "wrong export profile" (create ~profile:{profile with id="different"} ());
  List.iter (fun candidate_report ->
      error "candidate contract/profile mismatch" (create ~candidate_report:(Some candidate_report) ()))
    [{base_report with frozen_spec=None};
     {base_report with frozen_spec=Some {frozen with canonical=canonical ^ " "}};
     {base_report with frozen_spec=Some {frozen with schema_version=2}};
     {base_report with assurance=None};
     {base_report with assurance=Some {profile="different";status=Within_profile;findings=[]}};
     {base_report with assurance=Some {profile=profile.id;status=Unsupported;findings=[]}}];
  error "empty candidate trace" (create ~trace:(Some {trace with candidate=[]}) ());
  error "candidate execution prefix cannot end silently"
    (create ~trace:(Some {trace with candidate=List.map (fun (e : Contract_verify.trace_entry) -> {e with execution=Not_executed}) candidate}) ());
  error "candidate phase order cannot change" (create ~trace:(Some {trace with candidate=List.rev candidate}) ());
  error "candidate report must match trace outcome"
    (create ~trace:(Some (failed_trace (failed_candidate 0 Solve.Proved))) ());
  let continued = List.mapi (fun index (row : Contract_verify.trace_entry) ->
      if index=0 then {row with execution=Executed Solve.Proved} else row) candidate in
  error "cannot execute after decisive candidate result"
    (create ~trace:(Some {trace with candidate=continued}) ());
  let first = List.hd candidate in
  error "duplicate IDs within candidate"
    (create ~trace:(Some {trace with candidate=first::candidate}) ());
  error "duplicate IDs across stages"
    (create ~trace:(Some {trace with preservation={preservation with id=first.obligation.id}}) ());
  List.iter (fun id ->
      error "unsafe preservation ID" (create ~trace:(Some {trace with preservation={preservation with id}}) ());
      let unsafe = {first with obligation={first.obligation with id}} in
      error "unsafe candidate ID" (create ~trace:(Some {trace with candidate=unsafe::List.tl candidate}) ()))
    ["";"../escape";"nested/id";"bad\nname"]

let read_file path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel)
    (fun () -> really_input_string channel (in_channel_length channel))

let rec cleanup path = match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR -> Array.iter (fun name -> cleanup (Filename.concat path name)) (Sys.readdir path);Unix.rmdir path
  | _ -> Unix.unlink path

let write_checks () =
  let base = Filename.temp_file "soundcheck-comparison-evidence-" "" in
  Unix.unlink base;Unix.mkdir base 0o700;
  Fun.protect ~finally:(fun () -> cleanup base) (fun () ->
      let bundle = create () |> ok in
      let target = Filename.concat base "complete" in
      Evidence.write ~directory:target bundle |> ok;
      List.iter (fun (path,contents) ->
          check ("exact file " ^ path) (read_file (Filename.concat target path)=contents)) (Evidence.files bundle);
      error "existing comparison directory" (Evidence.write ~directory:target bundle);
      let too_long = {trace with preservation={preservation with id=String.make 1000 'p'}} in
      let incomplete = create ~trace:(Some too_long) () |> ok in
      let failed = Filename.concat base "incomplete" in
      error "comparison payload write failure" (Evidence.write ~directory:failed incomplete);
      check "failed write has no completion marker" (not (Sys.file_exists (Filename.concat failed "manifest.json"))))

let () =
  binding_checks ();
  stage_checks ();
  boundary_checks ();
  write_checks ();
  Printf.printf "%d comparison evidence checks passed\n" !checks
