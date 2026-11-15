open Soundcheck_core
module K = Soundcheck_kubernetes_rbac
module I = K.Input

let checks = ref 0
let check label yes = incr checks; if not yes then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let strings xs = `A (List.map (fun x -> `String x) xs)
let field key = function `O xs -> List.assoc key xs | _ -> failwith ("object expected: "^key)
let string key value = I.str key (field key value)
let array key value = I.arr key (field key value)
let contains value part =
  let rec loop n = n+String.length part<=String.length value &&
    (String.sub value n (String.length part)=part || loop (n+1)) in loop 0
let read path = let c=open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr c) (fun () -> really_input_string c (in_channel_length c))
let write path source = let c=open_out_bin path in
  Fun.protect ~finally:(fun () -> close_out_noerr c) (fun () -> output_string c source)
let mkdir path = Unix.mkdir path 0o700
let rec cleanup path = match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR -> Array.iter (fun x -> cleanup (Filename.concat path x)) (Sys.readdir path);Unix.rmdir path
  | _ -> Unix.unlink path
let temporary_directory () =
  let path=Filename.temp_file "soundcheck-rbac-sequence-adapters-" "" in
  Unix.unlink path;mkdir path;Unix.realpath path
let run ?env binary args =
  let output=Filename.temp_file "rbac-sequence-out-" "" and error=Filename.temp_file "rbac-sequence-err-" "" in
  Fun.protect ~finally:(fun () -> List.iter Sys.remove [output;error]) (fun () ->
    let out=Unix.openfile output [Unix.O_WRONLY;Unix.O_TRUNC] 0o600
    and err=Unix.openfile error [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let argv=Array.of_list (binary::args) in
    let pid=match env with None -> Unix.create_process binary argv Unix.stdin out err
      | Some env -> Unix.create_process_env binary argv env Unix.stdin out err in
    Unix.close out;Unix.close err;
    let _,status=Unix.waitpid [] pid in
    (match status with Unix.WEXITED code -> code | _ -> failwith "child terminated"),read output,read error)

type child={pid:int;input:out_channel;output:Unix.file_descr;error:string;mutable pending:string;mutable reaped:bool}
let with_child directory binary args action =
  let ir,iw=Unix.pipe ~cloexec:true () and or_,ow=Unix.pipe ~cloexec:true () in
  let error=Filename.concat directory "mcp.stderr" in
  let err=Unix.openfile error [Unix.O_WRONLY;Unix.O_CREAT;Unix.O_TRUNC] 0o600 in
  let pid=Unix.create_process binary (Array.of_list (binary::args)) ir ow err in
  List.iter Unix.close [ir;ow;err];
  let child={pid;input=Unix.out_channel_of_descr iw;output=or_;error;pending="";reaped=false} in
  Fun.protect ~finally:(fun () -> close_out_noerr child.input;
    if not child.reaped then begin (try Unix.kill pid Sys.sigkill with Unix.Unix_error (Unix.ESRCH,_,_) -> ());ignore (Unix.waitpid [] pid) end;
    Unix.close child.output) (fun () -> action child)
let send child value=output_string child.input (I.json value);output_char child.input '\n';flush child.input
let receive child =
  let deadline=Unix.gettimeofday ()+.45. in
  let rec loop ()=match String.index_opt child.pending '\n' with
    | Some n -> let line=String.sub child.pending 0 n in
      child.pending<-String.sub child.pending (n+1) (String.length child.pending-n-1);I.parse line
    | None -> let timeout=deadline-.Unix.gettimeofday () in
      if timeout<=0. || (let ready,_,_=Unix.select [child.output] [] [] timeout in ready=[]) then failwith "MCP timed out";
      let bytes=Bytes.create 4096 in let count=Unix.read child.output bytes 0 (Bytes.length bytes) in
      if count=0 then failwith ("MCP exited: "^read child.error);
      child.pending<-child.pending^Bytes.sub_string bytes 0 count;loop () in loop ()
let exchange child id method_ params =
  send child (`O ["jsonrpc",`String "2.0";"id",`Number (string_of_int id);"method",`String method_;"params",params]);
  let response=receive child in
  check "MCP envelope preserved" (field "jsonrpc" response=`String "2.0" && field "id" response=`Number (string_of_int id));response

let fixture = Sys.argv.(3)
let source name = read (Filename.concat fixture (name^".json"))
let contract = source "contract"
let before = source "before"
let spec = ok (K.Sequence_spec.of_string contract)
let replace key value = function `O xs -> `O ((key,value)::List.remove_assoc key xs) | _ -> assert false
let cases = ["repaired","valid_sequence",0;"authorization-failed","authorization_failed",3;
  "contract-failed","contract_failed",3;"out-of-scope-regression","out_of_scope_regression",3;
  "intermediate-regression","out_of_scope_regression",3;"before","unknown",4]
let profile = "kubernetes-rbac-v1.34-policy-sequence-v1"
let assert_report expected after report =
  check "new outer result schema" (field "schema_version" report=`Number "1" &&
    string "kind" report=K.Sequence_spec.kind && string "result" report=expected);
  check "new policy-sequence profile" (string "profile" (field "assurance" report)=profile);
  check "frozen ordered operations and nested requirements bound"
    (string "canonical" (field "frozen_spec" report)=K.Sequence_spec.canonical spec);
  let inputs=field "inputs" report in
  check "exact original bytes bound" (string "sha256" (field "before" inputs)=Sha256.string before);
  check "exact candidate bytes bound" (string "sha256" (field "after" inputs)=Sha256.string after);
  let intermediate=after=source "intermediate-regression" in
  let phase,step=match expected with
    | "valid_sequence" -> "complete",`Null
    | "authorization_failed" -> "authorization",`Number "1"
    | "unknown" -> "preparation",`Number "1"
    | _ when intermediate -> "intermediate_preservation",`Number "1"
    | _ -> "final_verification",`Number "2" in
  check "phase and step identify the checked obligation"
    (string "phase" report=phase && field "failing_step" report=step);
  let steps=array "steps" report and states=array "states" report in
  if expected="unknown" then check "unsupported plan has no invented state chain" (steps=[] && states=[])
  else begin
    check "complete bounded state chain" (List.length steps=2 && List.length states=3);
    List.iteri (fun index step ->
      check "frozen order retained" (field "index" step=`Number (string_of_int (index+1)) &&
        string "name" (field "target" step)=(if index=0 then "app-reader" else "app-reader-secondary"));
      let inputs=field "inputs" step in
      check "step before hash bound to preceding state" (field "before" inputs=field "digest" (List.nth states index));
      check "step after hash bound to succeeding state" (field "after" inputs=field "digest" (List.nth states (index+1)));
      let authorization=field "authorization" step in
      if expected="authorization_failed" && index=1 then
        check "later authorization left unexecuted" (authorization=`Null)
      else begin
        check "authorization method explicit" (string "method" authorization="deterministic-native-rbac-policy-coverage");
        check "authorization verdict" (field "allowed" authorization=`Bool (expected<>"authorization_failed"));
        let attrs=field "attributes" (field "initial" authorization) in
        check "initial request refers to this target" (string "verb" attrs="update" &&
          string "name" attrs=string "name" (field "target" step));
        if expected="authorization_failed" then
          check "uncovered native policy retained" (List.length (array "missing" (field "coverage" authorization))=1)
      end) steps;
    let prefixes=array "intermediate_preservation" report in
    check "every intermediate obligation retained" (List.length prefixes=1);
    let prefix=List.hd prefixes in
    check "prefix preservation always uses original baseline" (field "before" (field "inputs" prefix)=field "before" inputs);
    check "prefix status follows gate short circuit" (string "status" prefix=
      if intermediate then "violated" else if expected="valid_sequence" then "proved" else "not_executed")
  end;
  let verification=field "verification" report in
  if expected="authorization_failed" || expected="unknown" then
    check "solver stage skipped after rejected or unsupported plan" (verification=`Null)
  else begin
    let candidate=field "candidate_report" verification and comparison=field "comparison_report" verification in
    List.iter (fun report -> check "nested existing report unchanged" (field "schema_version" report=`Number "10" &&
      string "canonical" (field "frozen_spec" report)=K.Contract_spec.canonical (K.Sequence_spec.requirements spec))) [candidate;comparison];
    check "candidate stage verdict" (string "result" candidate=(if expected="contract_failed" then "violated" else "proved"));
    check "final comparison stage verdict" (string "result" comparison=
      (if expected="valid_sequence" || intermediate then "proved" else "violated"));
    if expected="out_of_scope_regression" then begin
      let failed=if intermediate then field "report" (List.hd (array "intermediate_preservation" report)) else comparison in
      check "unapproved permission witness retained"
        (string "resource_kind" (field "object_request" (field "counterexample" failed))="pods")
    end
  end

let evidence_checks directory before after stdout =
  let manifest=I.parse (read (Filename.concat directory "manifest.json")) in
  check "distinct evidence schema and kind" (field "schema_version" manifest=`Number "1" &&
    string "kind" manifest="kubernetes-rbac-policy-sequence-evidence");
  let inputs=field "inputs" manifest in
  List.iter (fun (name,source) -> check "manifest input hash" (string "sha256" (field name inputs)=Sha256.string source))
    ["before",before;"after",after];
  List.iter (fun item -> let path=Filename.concat directory (string "path" item) in
    let bytes=read path in
    check "every evidence artifact hashes exact bytes" (string "sha256" item=Sha256.string bytes);
    check "artifact length exact" (field "bytes" item=`Number (string_of_int (String.length bytes)));
    check "private artifact permissions" ((Unix.stat path).st_perm land 0o077=0)) (array "artifacts" manifest);
  check "report saved without rerun" (read (Filename.concat directory "report.json")=stdout);
  check "whole sequence contract saved" (read (Filename.concat directory "contract.json")=K.Sequence_spec.canonical spec^"\n");
  check "complete profile saved" (read (Filename.concat directory "profile.json")=K.Policy_sequence.profile_json^"\n");
  let report=I.parse stdout in
  check "evidence phase/step agree with report"
    (field "phase" manifest=field "phase" report && field "failing_step" manifest=field "failing_step" report);
  List.iteri (fun index state ->
    let path=Filename.concat directory (Printf.sprintf "states/state-%03d.json" index) in
    let bytes=read path in
    check "replayable state bytes match report digest" (string "sha256" (field "digest" state)=Sha256.string bytes);
    ignore (ok (K.Snapshot.of_string bytes))) (array "states" report);
  List.iter (fun entry ->
    let query=read (Filename.concat directory (string "query" entry)) in
    check "prefix formula retained even when skipped" (contains query "check-sat");
    let report_path=field "report" entry in
    if string "status" entry="not_executed" then check "skipped prefix has no fabricated report" (report_path=`Null)
    else check "executed prefix report retained" (report_path<>`Null)) (array "intermediate_preservation" manifest);
  if field "verification" report=`Null then begin
    check "unexecuted evidence explicit" (string "verification" manifest="not_executed");
    check "no invented solver plan" (not (Sys.file_exists (Filename.concat directory "verification")))
  end else begin
    let nested=I.parse (read (Filename.concat directory "verification/manifest.json")) in
    check "original comparison evidence schema" (field "schema_version" nested=`Number "3");
    check "nested final report exact" (I.parse (read (Filename.concat directory "verification/report.json"))=
      field "comparison_report" (field "verification" report));
    check "nested candidate report exact" (I.parse (read (Filename.concat directory "verification/candidate-report.json"))=
      field "candidate_report" (field "verification" report));
    let artifact item = let bytes=read (Filename.concat directory ("verification/"^string "path" item)) in
      check "nested artifact hash" (Sha256.string bytes=string "sha256" item);bytes in
    check "nested frozen access identity" (artifact (field "contract" nested)=K.Contract_spec.canonical (K.Sequence_spec.requirements spec)^"\n");
    let entries=array "obligations" nested in
    check "complete candidate and preservation plan retained" (List.length entries>3);
    List.iter (fun entry -> ignore (artifact (field "query" entry))) entries;
    let preservation=List.find (fun e -> string "phase" e="preservation") entries in
    if string "result" report="contract_failed" then
      check "failed contract skips preservation" (field "execution" preservation=`String "not_executed")
    else check "successful candidate executes preservation" (field "execution" preservation=`String "executed")
  end

let mcp_checks directory binary =
  let cp=Filename.concat directory "mcp-contract.json" and bp=Filename.concat directory "mcp-baseline.json" in
  write cp contract;write bp before;
  let code,_,_=run binary ["mcp";"--connector";"kubernetes-rbac";"--contract";cp] in
  check "sequence MCP requires original snapshot" (code=2);
  with_child directory binary ["mcp";"--connector";"kubernetes-rbac";"--contract";cp;"--baseline";bp] (fun child ->
    ignore (field "result" (exchange child 1 "initialize" (`O ["protocolVersion",`String "2024-11-05";
      "capabilities",`O [];"clientInfo",`O ["name",`String "policy-sequence-acceptance";"version",`String "1"]])));
    send child (`O ["jsonrpc",`String "2.0";"method",`String "notifications/initialized"]);
    let tools=array "tools" (field "result" (exchange child 2 "tools/list" (`O []))) in
    check "MCP exposes only frozen sequence gate" (List.map (string "name") tools=["sequence"]);
    let schema=field "inputSchema" (List.hd tools) in
    check "candidate-only schema" (field "required" schema=strings ["config"] && field "additionalProperties" schema=`Bool false);
    write cp (source "reverse-contract");write bp (source "repaired");Sys.remove cp;Sys.remove bp;
    List.iteri (fun index (name,expected,_) ->
      let result=field "result" (exchange child (3+index) "tools/call" (`O ["name",`String "sequence";
        "arguments",`O ["config",`String (source name)]])) in
      let report=field "structuredContent" result in
      check "text/structured output agree" (I.parse (string "text" (List.hd (array "content" result)))=report);
      assert_report expected (source name) report) cases;
    List.iteri (fun index override ->
      let response=exchange child (20+index) "tools/call" (`O ["name",`String "sequence";
        "arguments",`O ["config",`String (source "repaired");override,`String "replacement"]]) in
      check ("immutable MCP "^override) (field "code" (field "error" response)=`Number "-32602"))
      ["actor";"steps";"target";"operation";"requirements";"contract";"baseline";"evidence_dir"];
    List.iteri (fun index name -> let response=exchange child (40+index) "tools/call"
        (`O ["name",`String name;"arguments",`O ["config",`String before]]) in
      check "sequence mode cannot select other tools" (field "code" (field "error" response)=`Number "-32602")) ["verify";"compare";"change"];
    close_out child.input;let _,status=Unix.waitpid [] child.pid in child.reaped<-true;
    check "MCP clean exit" (status=Unix.WEXITED 0 && read child.error=""))

let gate_checks directory binary helper =
  let workspace=Filename.concat directory "workspace" and action=Filename.concat directory "action"
  and temp=Filename.concat directory "runner-temp" in
  List.iter mkdir [workspace;action;temp];
  List.iter (fun p -> mkdir (Filename.concat action p)) ["scripts";"_build";"_build/default";"_build/default/cli"];
  let script=Filename.concat action "scripts/verify-approved-contract.sh" in write script (read helper);
  Unix.symlink (Unix.realpath binary) (Filename.concat action "_build/default/cli/main.exe");
  let git args=let code,out,err=run "git" (["-c";"core.hooksPath=/dev/null";"-C";workspace]@args) in
    check ("fixture git: "^err) (code=0);String.trim out in
  ignore (git ["init";"--quiet"]);
  let cp=Filename.concat workspace "contract.json" and sp=Filename.concat workspace "snapshot.json" in
  write cp contract;write sp before;ignore (git ["add";"--";"contract.json";"snapshot.json"]);
  ignore (git ["-c";"user.name=Soundcheck acceptance";"-c";"user.email=acceptance@example.invalid";
    "-c";"commit.gpgSign=false";"commit";"--quiet";"-m";"Approved policy operation"]);
  let approved=git ["rev-parse";"HEAD"] and event=Filename.concat directory "event.json" in
  write event (I.json (`O ["repository",`O ["full_name",`String "example/soundcheck"];
    "pull_request",`O ["base",`O ["sha",`String approved;"ref",`String "main";
      "repo",`O ["full_name",`String "example/soundcheck"]]]]));
  let settings=["GITHUB_WORKSPACE",workspace;"GITHUB_EVENT_PATH",event;"GITHUB_EVENT_NAME","pull_request";
    "GITHUB_REPOSITORY","example/soundcheck";"GITHUB_BASE_REF","main";"RUNNER_TEMP",temp;
    "SOUNDCHECK_CONFIG_INPUT","snapshot.json";"SOUNDCHECK_CONTRACT_INPUT","contract.json";
    "SOUNDCHECK_CONNECTOR_INPUT","kubernetes-rbac";"SOUNDCHECK_MODE_INPUT","sequence"] in
  let execute ?(overrides=[]) () =
    let settings=overrides@List.filter (fun (key,_) -> not (List.mem_assoc key overrides)) settings in
    let inherited=Array.to_list (Unix.environment ()) |> List.filter (fun value ->
      not (List.exists (fun (key,_) -> String.starts_with ~prefix:(key^"=") value) settings)) in
    let env=Array.of_list (List.map (fun (key,value)->key^"="^value) settings@inherited) in
    run ~env "bash" [script] in
  List.iter (fun (name,expected,code) ->
    write sp (source name);write cp "{}";
    let actual,out,err=execute () in
    check ("trusted gate "^name^": "^err) (actual=code && err="");
    List.iter (fun part -> check ("gate binds "^part) (contains out part))
      ["Approved contract: "^approved^":contract.json";"Approved baseline: "^approved^":snapshot.json";
       "\"result\":\""^expected^"\"";profile];
    check "candidate cannot replace contract; temp inputs removed" (read cp="{}" && Sys.readdir temp=[||])) cases;
  List.iter (fun (overrides,reason) -> let code,_,err=execute ~overrides () in
    check "sequence gate invalid source/mode rejected" (code=1 && contains err reason))
    [["SOUNDCHECK_CONNECTOR_INPUT","kong"],"sequence mode requires the kubernetes-rbac connector";
     ["GITHUB_EVENT_NAME","push"],"sequence mode requires a pull_request event"];
  (* A candidate can weaken preservation locally, but the trusted gate ignores it. *)
  let value=I.parse contract in let req=field "requirements" value in
  let added=`O ["subject",`String "app";"namespace",`String "team-a";"resource",`String "pods";"names",`Null;
    "request_kind",`String "resource";"operation",`String "get";"api_group",`String "";"subresource",`String ""] in
  let weakened=replace "requirements" (replace "change_scope" (`A (array "change_scope" req@[added])) req) value |> I.json in
  write cp weakened;write sp (source "out-of-scope-regression");
  let bp=Filename.concat directory "baseline.json" in write bp before;
  let code,_,_=run binary ["rbac";"sequence";bp;sp;"--contract";cp;"--format";"json"] in
  check "control: weakened scope hides unrelated loss" (code=0);
  let code,out,err=execute () in
  check "approved whole sequence contract blocks candidate weakening" (code=3 && err="" && contains out "out_of_scope_regression");
  write cp (source "reverse-contract");write sp (source "intermediate-regression");
  let code,_,_=run binary ["rbac";"sequence";bp;sp;"--contract";cp;"--format";"json"] in
  check "control: changed order avoids the temporary workflow loss" (code=0);
  let code,out,err=execute () in
  check "approved step order cannot be replaced in candidate contract"
    (code=3 && err="" && contains out "intermediate_preservation");
  write cp (replace "actor" (`String "app") (I.parse contract) |> I.json);write sp (source "repaired");
  let code,out,err=execute () in
  check "approved actor cannot be replaced in candidate contract"
    (code=0 && err="" && contains out "valid_sequence")

let () =
  let binary=Sys.argv.(1) and helper=Sys.argv.(2) in
  let directory=temporary_directory () in
  Fun.protect ~finally:(fun () -> cleanup directory) (fun () ->
    let cp=Filename.concat directory "contract.json" and bp=Filename.concat directory "before.json" in
    write cp contract;write bp before;
    let code,out,err=run binary ["rbac";"check-contract";cp] in
    check "human review includes exact frozen operation and nested scope"
      (code=0 && err="" && contains out "Frozen RBAC policy sequence" && contains out "update-existing" && contains out "structure only");
    List.iter (fun (name,expected,code) ->
      let ap=Filename.concat directory (name^"-candidate.json") and evidence=Filename.concat directory (name^"-evidence") in
      write ap (source name);
      let args=["rbac";"sequence";bp;ap;"--contract";cp;"--format";"json";"--evidence-dir";evidence] in
      let actual,out,err=run binary args in
      check ("CLI "^name^": "^err) (actual=code && err="");
      assert_report expected (source name) (I.parse out);evidence_checks evidence before (source name) out;
      let old=read (Filename.concat evidence "manifest.json") in
      let actual,_,err=run binary args in
      check "existing evidence never overwritten" (actual=1 && contains err "evidence error" &&
        read (Filename.concat evidence "manifest.json")=old)) cases;
    let ap=Filename.concat directory "human-candidate.json" in
    write ap (source "intermediate-regression");
    let code,out,err=run binary ["rbac";"sequence";bp;ap;"--contract";cp] in
    check "human output locates temporary preservation failure"
      (code=3 && err="" && contains out "intermediate_preservation" && contains out "step 1" && contains out profile);
    List.iter (fun override ->
      let code,_,_=run binary (["rbac";"sequence";bp;ap;"--contract";cp]@override) in
      check "CLI cannot override frozen sequence components" (code=2))
      [["--actor";"app"];["--steps";"[]"];["--baseline";ap];["--contract-version";"1"]];
    List.iter (fun format ->
      let code,out,err=run binary ["profile";"kubernetes-rbac-policy-sequence";"--format";format] in
      check "sequence assurance profile exposed" (code=0 && err="" && contains out profile)) ["human";"json"];
    let code,_,_=run binary ["profile";"kubernetes-rbac-policy-sequence";"--contract-version";"10"] in
    check "sequence profile cannot override nested access schema" (code=2);
    List.iter (fun (contract_name,before_name,after_name,expected,phase,code) ->
      let cp=Filename.concat directory "extra-contract.json" and bp=Filename.concat directory "extra-before.json"
      and ap=Filename.concat directory "extra-after.json" in
      write cp (source contract_name);write bp (source before_name);write ap (source after_name);
      let actual,out,err=run binary ["rbac";"sequence";bp;ap;"--contract";cp;"--format";"json"] in
      let report=I.parse out in
      check "order and transient-grant controls" (actual=code && err="" && string "result" report=expected && string "phase" report=phase))
      ["reverse-contract","before","intermediate-regression","valid_sequence","complete",0;
       "transient-gain-contract","transient-gain-before","transient-gain-after","out_of_scope_regression","intermediate_preservation",3];
    let invalid=replace "actor" (`String "unreviewed") (I.parse contract) |> I.json in
    write cp invalid;
    List.iter (fun args -> let code,_,err=run binary args in
      check "sequence kind retains specific parser diagnostic" (code=2 && contains err "sequence_contract" && contains err "actor"))
      [["rbac";"check-contract";cp];["mcp";"--connector";"kubernetes-rbac";"--contract";cp;"--baseline";bp]];
    write cp contract;
    let fake_z3=Filename.concat directory "fake-z3" in
    write fake_z3 "#!/bin/sh\nif [ \"$1\" = -version ]; then printf 'Z3 version selected-solver-fixture\\n'; exit 0; fi\nexit 1\n";
    Unix.chmod fake_z3 0o700;
    let report=K.Policy_sequence.run ~z3:fake_z3 spec ~before ~after:(source "repaired") in
    check "solver failure never produces valid sequence" (K.Policy_sequence.exit_code report=4 && string "result" (I.parse (K.Policy_sequence.to_json report))="unknown");
    let evidence=Filename.concat directory "selected-solver-evidence" in
    ignore (ok (K.Policy_sequence.write_evidence ~directory:evidence report));
    let manifest=I.parse (read (Filename.concat evidence "manifest.json")) in
    check "evidence identifies the selected solver, not PATH default"
      (string "value" (field "z3_version" (field "provenance" manifest))="Z3 version selected-solver-fixture");
    let nested=I.parse (read (Filename.concat evidence "verification/manifest.json")) in
    check "nested evidence uses the same selected solver" (string "version" (field "solver" nested)="Z3 version selected-solver-fixture");
    let report=K.Policy_sequence.run ~z3:"/nonexistent/solver" spec ~before ~after:(source "authorization-failed") in
    check "authorization failure short circuits solver" (K.Policy_sequence.exit_code report=3);
    mcp_checks directory binary;gate_checks directory binary helper);
  Printf.printf "policy-sequence adapters: %d checks passed\n" !checks
