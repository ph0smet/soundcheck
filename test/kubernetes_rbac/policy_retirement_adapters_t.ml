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
  let path=Filename.temp_file "soundcheck-rbac-retirement-adapters-" "" in
  Unix.unlink path;mkdir path;Unix.realpath path
let run ?env binary args =
  let output=Filename.temp_file "rbac-retirement-out-" "" and error=Filename.temp_file "rbac-retirement-err-" "" in
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

let fixture=Sys.argv.(3)
let source name=read (Filename.concat fixture (name^".json"))
let replace key value = function `O xs -> `O ((key,value)::List.remove_assoc key xs) | _ -> assert false
let remove key = function `O xs -> `O (List.remove_assoc key xs) | _ -> assert false
let sequence_canonical text=K.Sequence_spec.canonical (ok (K.Sequence_spec.of_string text))
let change_canonical text=K.Change_spec.canonical (ok (K.Change_spec.of_string text))
type case={id:string;mode:string;contract:string;baseline:string;candidate:string;
           result:string;phase:string;step:int option;code:int}
let seq ?(contract="contract") ?(baseline="before") id candidate result phase step code =
  {id;mode="sequence";contract;baseline;candidate;result;phase;step;code}
let change ?(contract="delete-contract") ?(baseline="delete-before") id candidate result code =
  {id;mode="change";contract;baseline;candidate;result;phase="";step=None;code}
let cases=[
  seq "migration" "repaired" "valid_sequence" "complete" None 0;
  seq "uncovered-grant" "authorization-failed" "authorization_failed" "authorization" (Some 1) 3;
  seq "required-access-loss" "contract-failed" "contract_failed" "final_verification" (Some 4) 3;
  seq "unapproved-grant" "out-of-scope-regression" "out_of_scope_regression" "final_verification" (Some 4) 3;
  seq "missing-replacements" "before" "unknown" "preparation" (Some 1) 4;
  seq ~contract:"gap-contract" "remove-before-replacement" "repaired" "invariant_failed" "state_invariants" (Some 1) 3;
  seq ~contract:"unguarded-gap-contract" "explicit-final-only" "repaired" "valid_sequence" "complete" None 0;
  seq ~baseline:"initial-before" "initial-required-access-loss" "repaired" "invariant_failed" "state_invariants" (Some 0) 3;
  seq ~contract:"role-first-contract" "unresolved-intermediate-reference" "repaired" "unknown" "preparation" (Some 1) 4;
  seq ~contract:"revoked-actor-contract" "revoked-prior-authority" "revoked-actor-after" "authorization_failed" "authorization" (Some 2) 3;
  seq ~contract:"handoff-contract" ~baseline:"handoff-before" "handoff" "handoff-repaired" "valid_sequence" "complete" None 0;
  seq ~contract:"handoff-contract" ~baseline:"handoff-before" "handoff-gap" "handoff-invariant-failed" "invariant_failed" "state_invariants" (Some 1) 3;
  change "delete-binding" "delete-after" "valid_change" 0;
  change ~contract:"delete-role-contract" ~baseline:"delete-after" "delete-role" "repaired" "valid_change" 0;
  change ~contract:"delete-unauthorized-contract" "delete-without-authority" "delete-after" "authorization_failed" 3;
]
let frozen case=if case.mode="sequence" then sequence_canonical (source case.contract) else change_canonical (source case.contract)
let profile case="kubernetes-rbac-v1.34-policy-"^case.mode^"-v2"
let assert_report case report =
  check (case.id^" new outer schema") (field "schema_version" report=`Number "2");
  check (case.id^" exact result") (string "result" report=case.result);
  check (case.id^" explicit profile") (string "profile" (field "assurance" report)=profile case);
  check (case.id^" bound frozen identity") (field "schema_version" (field "frozen_spec" report)=`Number "2"
    && string "canonical" (field "frozen_spec" report)=frozen case);
  List.iter (fun (key,filename) -> check (case.id^" exact "^key^" bytes")
    (string "sha256" (field key (field "inputs" report))=Sha256.string (source filename)))
    ["before",case.baseline;"after",case.candidate];
  if case.mode="change" then begin
    let authorization=field "authorization" report in
    check "deletion authorization has no bind/escalate/coverage requirement"
      (field "special" authorization=`Null && field "coverage" authorization=`Null);
    let attrs=field "attributes" (field "initial" authorization) in
    let target=field "target" (I.parse (source case.contract)) in
    check "deletion uses exact named request" (string "verb" attrs="delete" &&
      string "name" attrs=string "name" target && string "namespace" attrs=string "namespace" target)
  end else begin
    check (case.id^" execution phase") (string "phase" report=case.phase);
    check (case.id^" failing completed step including baseline") (field "failing_step" report=
      match case.step with None -> `Null | Some n -> `Number (string_of_int n));
    let states=array "states" report and steps=array "steps" report in
    if case.phase="preparation" then check "unsupported plan invents no states" (states=[] && steps=[])
    else begin
      let spec=ok (K.Sequence_spec.of_string (source case.contract)) in
      let count=List.length (K.Sequence_spec.steps spec) in
      check "all bounded states retained" (List.length states=count+1 && List.length steps=count);
      List.iteri (fun i step ->
        check "step follows preceding state's bytes" (field "before" (field "inputs" step)=field "digest" (List.nth states i));
        check "step produces succeeding state's bytes" (field "after" (field "inputs" step)=field "digest" (List.nth states (i+1)));
        let authorization=field "authorization" step in
        if string "operation" step="delete-existing" && authorization<>`Null then begin
          check "sequence deletion has no invented special check"
            (field "special" authorization=`Null && field "coverage" authorization=`Null);
          let attrs=field "attributes" (field "initial" authorization) in
          check "sequence deletion exact name and verb"
            (string "verb" attrs="delete" && string "name" attrs=string "name" (field "target" step))
        end) steps;
      let invariants=array "state_invariants" report in
      if K.Sequence_spec.invariants spec=[] then check "explicit empty invariant selection" (invariants=[])
      else begin
        check "every state invariant obligation retained" (List.length invariants=count+1);
        List.iteri (fun i invariant ->
          check "invariant state order includes S0" (field "state" invariant=`Number (string_of_int i));
          let expected=if case.phase="complete" then "proved"
            else if case.phase="state_invariants" then
              let failed=Option.get case.step in if i<failed then "proved" else if i=failed then "violated" else "not_executed"
            else "not_executed" in
          check (case.id^" invariant short-circuit status") (string "status" invariant=expected);
          let nested=field "report" invariant in
          if expected="not_executed" then check "unexecuted invariant has no fake report" (nested=`Null)
          else begin
            check "invariant report binds whole sequence"
              (string "canonical" (field "frozen_spec" nested)=frozen case);
            check "invariant report has a distinct property" (string "property" nested="rbac-sequence-invariants");
            if expected="violated" then begin
              check "invariant identifies selected access clause" (string "name" (field "clause" nested)="configmaps-required");
              check "invariant retains a ConfigMap witness"
                (string "resource_kind" (field "object_request" (field "counterexample" nested))="configmaps")
            end
          end) invariants
      end
    end;
    if case.result="invariant_failed" then begin
      let final=field "verification" report in
      check "invariant distinguishes final-valid candidate"
        (string "result" (field "candidate_report" final)="proved" && string "result" (field "comparison_report" final)="proved");
      List.iter (fun entry -> check "invariant failure leaves later preservation unexecuted"
        (string "status" entry="not_executed")) (array "intermediate_preservation" report)
    end
  end

let evidence_checks case directory stdout =
  let manifest=I.parse (read (Filename.concat directory "manifest.json")) in
  check "versioned retirement evidence schema" (field "schema_version" manifest=`Number "2");
  check "exact single-run report persisted" (read (Filename.concat directory "report.json")=stdout);
  check "entire frozen contract persisted" (read (Filename.concat directory "contract.json")=frozen case^"\n");
  let profile_json=if case.mode="sequence" then K.Policy_sequence.profile_json_for_version 2
    else K.Policy_change.profile_json_for_version 2 in
  check "matching profile persisted" (read (Filename.concat directory "profile.json")=profile_json^"\n");
  let artifacts=array "artifacts" manifest in
  List.iter (fun artifact ->
    let path=Filename.concat directory (string "path" artifact) in
    let bytes=read path in
    check "all payload digests exact" (string "sha256" artifact=Sha256.string bytes);
    check "all payload lengths exact" (field "bytes" artifact=`Number (string_of_int (String.length bytes)));
    check "private evidence files" ((Unix.stat path).st_perm land 0o077=0)) artifacts;
  check "private evidence directory" ((Unix.stat directory).st_perm land 0o077=0);
  if case.mode="sequence" then begin
    let report=I.parse stdout in
    check "manifest and report agree on phase" (field "phase" manifest=field "phase" report);
    List.iteri (fun i state ->
      let bytes=read (Filename.concat directory (Printf.sprintf "states/state-%03d.json" i)) in
      check "exact replayable state digest" (Sha256.string bytes=string "sha256" (field "digest" state));
      ignore (ok (K.Snapshot.of_string bytes))) (array "states" report);
    let invariant_entries=array "state_invariants" manifest in
    let report_entries=array "state_invariants" report in
    check "invariant manifest retains every planned state" (List.length invariant_entries=List.length report_entries);
    List.iteri (fun i entry ->
      let declared=List.nth report_entries i in
      check "invariant manifest state/status agree with report"
        (field "state" entry=field "state" declared && field "status" entry=field "status" declared
         && field "input" entry=field "input" declared);
      check "invariant input binds the replay state" (field "input" entry=field "digest" (List.nth (array "states" report) i));
      let prefix=Filename.concat directory (Printf.sprintf "invariants/state-%03d" i) in
      check "private nested invariant directory" ((Unix.stat prefix).st_perm land 0o077=0);
      if string "status" entry="not_executed" then begin
        check "skipped invariant has no verification manifest" (field "verification" entry=`Null &&
          not (Sys.file_exists (Filename.concat prefix "manifest.json")));
        let plan=I.parse (read (Filename.concat prefix "plan.json")) in
        check "unexecuted invariant plan binds exact state" (field "state" plan=field "state" entry &&
          field "input" plan=field "input" entry && string "status" plan="not_executed");
        let queries=array "queries" plan in
        check "skipped invariant retains a nonempty query plan" (queries<>[]);
        List.iter (fun query -> check "skipped invariant formula saved" (contains
          (read (Filename.concat prefix (string "path" query))) "check-sat")) queries
      end else begin
        check "executed invariant advertises verification evidence" (field "verification" entry<>`Null);
        check "executed invariant report saved without another run"
          (I.parse (read (Filename.concat prefix "report.json"))=field "report" declared);
        check "executed invariant retains full frozen sequence"
          (read (Filename.concat prefix "contract.json")=frozen case^"\n")
      end) invariant_entries;
    if case.result="invariant_failed" then begin
      check "invariant query evidence saved" (List.exists (fun item ->
        contains (string "path" item) "invariant" && Filename.check_suffix (string "path" item) ".smt2") artifacts);
      check "invariant manifest binds all states" (List.length invariant_entries=List.length (array "states" report))
    end
  end

let case_paths directory case =
  let cp=Filename.concat directory (case.id^"-contract.json") and bp=Filename.concat directory (case.id^"-before.json")
  and ap=Filename.concat directory (case.id^"-after.json") in
  write cp (source case.contract);write bp (source case.baseline);write ap (source case.candidate);cp,bp,ap

let mcp_checks directory binary =
  let base=List.find (fun c -> c.id="handoff") cases and failed=List.find (fun c -> c.id="handoff-gap") cases in
  let cp,bp,_=case_paths directory base in
  let code,_,_=run binary ["mcp";"--connector";"kubernetes-rbac";"--contract";cp] in
  check "schema2 sequence still requires original baseline" (code=2);
  with_child directory binary ["mcp";"--connector";"kubernetes-rbac";"--contract";cp;"--baseline";bp] (fun child ->
    ignore (field "result" (exchange child 1 "initialize" (`O ["protocolVersion",`String "2024-11-05";
      "capabilities",`O [];"clientInfo",`O ["name",`String "retirement-acceptance";"version",`String "1"]])));
    send child (`O ["jsonrpc",`String "2.0";"method",`String "notifications/initialized"]);
    let tools=array "tools" (field "result" (exchange child 2 "tools/list" (`O []))) in
    check "only the sequence tool" (List.map (string "name") tools=["sequence"]);
    let tool=List.hd tools in
    check "MCP describes original-state invariants" (contains (string "description" tool) "original" && contains (string "description" tool) "invariants");
    let schema=field "inputSchema" tool in
    check "MCP schema remains config only" (field "required" schema=strings ["config"] && field "additionalProperties" schema=`Bool false);
    write cp (replace "invariants" (`A []) (I.parse (source base.contract)) |> I.json);
    write bp (source base.candidate);Sys.remove cp;Sys.remove bp;
    List.iteri (fun i case ->
      let response=field "result" (exchange child (3+i) "tools/call" (`O ["name",`String "sequence";
        "arguments",`O ["config",`String (source case.candidate)]])) in
      let report=field "structuredContent" response in
      check "MCP text and structured report agree" (I.parse (string "text" (List.hd (array "content" response)))=report);
      assert_report case report) [base;failed;base;failed];
    List.iteri (fun i key ->
      let response=exchange child (20+i) "tools/call" (`O ["name",`String "sequence";
        "arguments",`O ["config",`String (source failed.candidate);key,`A []]]) in
      check ("MCP rejects mutable "^key) (field "code" (field "error" response)=`Number "-32602"))
      ["invariants";"schema_version";"steps";"actor";"requirements";"change_scope";"baseline";"contract"];
    close_out child.input;let _,status=Unix.waitpid [] child.pid in child.reaped<-true;
    check "MCP clean exit" (status=Unix.WEXITED 0 && read child.error=""));
  let case=List.find (fun c -> c.id="delete-binding") cases in
  let cp,bp,_=case_paths directory case in
  with_child directory binary ["mcp";"--connector";"kubernetes-rbac";"--contract";cp;"--baseline";bp] (fun child ->
    ignore (exchange child 1 "initialize" (`O ["protocolVersion",`String "2024-11-05";
      "capabilities",`O [];"clientInfo",`O ["name",`String "delete-acceptance";"version",`String "1"]]));
    send child (`O ["jsonrpc",`String "2.0";"method",`String "notifications/initialized"]);
    let response=field "result" (exchange child 2 "tools/call" (`O ["name",`String "change";
      "arguments",`O ["config",`String (source case.candidate)]])) in
    assert_report case (field "structuredContent" response);
    close_out child.input;let _,status=Unix.waitpid [] child.pid in child.reaped<-true;
    check "deletion MCP clean exit" (status=Unix.WEXITED 0 && read child.error=""))

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
  let base=List.find (fun c -> c.id="handoff") cases and failed=List.find (fun c -> c.id="handoff-gap") cases in
  write cp (source base.contract);write sp (source base.baseline);
  ignore (git ["add";"--";"contract.json";"snapshot.json"]);
  let commit ()=ignore (git ["-c";"user.name=Soundcheck acceptance";"-c";"user.email=acceptance@example.invalid";
    "-c";"commit.gpgSign=false";"commit";"--quiet";"-m";"Approved retirement contract"]);git ["rev-parse";"HEAD"] in
  let approved=commit () and event=Filename.concat directory "event.json" in
  let event_for sha=I.json (`O ["repository",`O ["full_name",`String "example/soundcheck"];
    "pull_request",`O ["base",`O ["sha",`String sha;"ref",`String "main";
      "repo",`O ["full_name",`String "example/soundcheck"]]]]) in
  write event (event_for approved);
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
  let bp=Filename.concat directory "trusted-before.json" in write bp (source base.baseline);
  let contract=I.parse (source base.contract) in
  let mutations=["drop invariant",replace "invariants" (`A []) contract;
    "reverse operation order",replace "steps" (`A (List.rev (array "steps" contract))) contract;
    "downgrade to legacy final-only",replace "schema_version" (`Number "1") (remove "invariants" contract)] in
  List.iter (fun (label,mutated) ->
    write cp (I.json mutated);write sp (source failed.candidate);
    let code,_,err=run binary ["rbac";"sequence";bp;sp;"--contract";cp;"--format";"json"] in
    check ("control permits weakened candidate: "^label^err) (code=0);
    let code,out,err=execute () in
    check ("trusted base rejects candidate contract tampering: "^label)
      (code=3 && err="" && contains out "invariant_failed" && contains out "state_invariants");
    check "approved contract and baseline refs bound" (contains out ("Approved contract: "^approved^":contract.json") &&
      contains out ("Approved baseline: "^approved^":snapshot.json"));
    check "trusted temporary files removed" (Sys.readdir temp=[||])) mutations;
  write cp "{}";write sp (source base.candidate);
  let code,out,err=execute () in
  check "approved schema2 valid candidate passes despite mutated contract" (code=0 && err="" && contains out "valid_sequence");
  let code,_,err=execute ~overrides:["GITHUB_EVENT_NAME","push"] () in
  check "retirement sequences remain PR-only" (code=1 && contains err "sequence mode requires a pull_request");
  let deletion=List.find (fun c -> c.id="delete-binding") cases in
  write cp (source deletion.contract);write sp (source deletion.baseline);
  ignore (git ["add";"--";"contract.json";"snapshot.json"]);
  let approved=commit () in write event (event_for approved);
  write cp "{}";write sp (source deletion.candidate);
  let code,out,err=execute ~overrides:["SOUNDCHECK_MODE_INPUT","change"] () in
  check "trusted base deletion gate passes exact frozen deletion" (code=0 && err="" && contains out "valid_change" &&
    contains out "delete-existing" && contains out "policy-change-v2")

let () =
  let binary=Sys.argv.(1) and helper=Sys.argv.(2) in
  let directory=temporary_directory () in
  Fun.protect ~finally:(fun () -> cleanup directory) (fun () ->
    List.iter (fun case ->
      let cp,bp,ap=case_paths directory case in
      let evidence=Filename.concat directory (case.id^"-evidence") in
      let args=["rbac";case.mode;bp;ap;"--contract";cp;"--format";"json";"--evidence-dir";evidence] in
      let actual,out,err=run binary args in
      check ("CLI "^case.id^": "^err^out) (actual=case.code && err="");
      assert_report case (I.parse out);evidence_checks case evidence out) cases;
    let case=List.find (fun c -> c.id="migration") cases in
    let cp,bp,ap=case_paths directory case in
    let code,out,err=run binary ["rbac";"check-contract";cp] in
    check "contract review includes deletion and invariant selection"
      (code=0 && err="" && contains out "delete-existing" && contains out "configmaps-required" && contains out "S0");
    List.iter (fun format ->
      let case=List.find (fun c -> c.id="initial-required-access-loss") cases in
      let cp,bp,ap=case_paths directory case in
      let code,out,err=run binary ["rbac";"sequence";bp;ap;"--contract";cp;"--format";format] in
      check "human/GitHub output exposes original-state failure" (code=3 && err="" && contains out "state_invariants" &&
        contains out "configmaps-required" && contains out "0")) ["human";"github"];
    List.iter (fun override ->
      let code,_,_=run binary (["rbac";"sequence";bp;ap;"--contract";cp]@override) in
      check "CLI cannot override transition requirements" (code=2))
      [["--invariants";"[]"];["--actor";"app"];["--steps";"[]"];["--contract-version";"1"]];
    List.iter (fun (selector,expected) -> List.iter (fun format ->
      let code,out,err=run binary ["profile";selector;"--format";format] in
      check "explicit profiles distinguish legacy/new versions" (code=0 && err="" && contains out expected)) ["human";"json"])
      ["kubernetes-rbac-policy-change","policy-change-v1";"kubernetes-rbac-policy-change-v2","policy-change-v2";
       "kubernetes-rbac-policy-sequence","policy-sequence-v1";"kubernetes-rbac-policy-sequence-v2","policy-sequence-v2"];
    List.iter (fun bad ->
      write cp (I.json bad);
      let code,_,err=run binary ["rbac";"check-contract";cp] in
      check "strict invariant contract review rejects tampering" (code=2 && contains err "contract check error"))
      [replace "invariants" (strings ["unreviewed-clause"]) (I.parse (source case.contract));
       replace "invariants" (strings ["configmaps-required";"configmaps-required"]) (I.parse (source case.contract));
       replace "schema_version" (`Number "1") (I.parse (source case.contract));
       remove "invariants" (I.parse (source case.contract))];
    mcp_checks directory binary;gate_checks directory binary helper);
  Printf.printf "policy-retirement adapters: %d checks passed\n" !checks
