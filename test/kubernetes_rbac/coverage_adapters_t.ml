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
  let path=Filename.temp_file "soundcheck-rbac-coverage-adapters-" "" in
  Unix.unlink path;mkdir path;Unix.realpath path
let run ?env binary args =
  let output=Filename.temp_file "rbac-coverage-out-" "" and error=Filename.temp_file "rbac-coverage-err-" "" in
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

let profile="kubernetes-rbac-v1.34-static-coverage-v1"
let api="rbac.authorization.k8s.io"
let resource ?(subject="app") ?(op="get") ?(group="acme.example") ?(raw="widgets")
    ?(sub="") ?(ns=`String "team-a") ?(names=strings ["required"]) () =
  ["request_kind",`String "resource";"subject",`String subject;"operation",`String op;
   "api_group",`String group;"resource",`String raw;"subresource",`String sub;"namespace",ns;"names",names]
let url ?(subject="app") path=
  ["request_kind",`String "non_resource";"subject",`String subject;"operation",`String "get";
   "paths",`O ["exact",`String path]]
let operator_change=resource ~subject:"operator" ~op:"patch" ~sub:"status" ~names:(strings ["managed"]) ()
let contract ?(version=9) ?(narrow=false) ?(extra_changes=[]) () =
  let clause name kind scope=`O (["name",`String name;"kind",`String kind]@scope) in
  let clauses,changes=if version=9 then
      [clause "custom-required" "must_allow" (resource ());
       clause "namespace-required" "must_allow" (resource ~group:"" ~raw:"namespaces" ~names:(strings ["team-a"]) ());
       clause "put-existing-required" "must_allow" (resource ~group:"" ~raw:"services" ~op:"update-existing" ~names:(strings ["web"]) ());
       clause "health-required" "must_allow" (url "/healthz");
       clause "metrics-forbidden" "must_not_grant" (url "/metrics")],
      [url "/metrics"]@extra_changes
    else
      let old fields=List.remove_assoc "request_kind" fields in
      [clause "config-required" "must_allow" (old (resource ~group:"" ~raw:"configmaps" ~names:(strings ["settings"]) ()));
       clause "secrets-forbidden" "must_not_grant" (old (resource ~group:"" ~raw:"secrets" ~names:`Null ()))],[] in
  I.json (`O (["schema_version",`Number (string_of_int version);"kind",`String "kubernetes-rbac-access";
    "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
      "identities",`A [`O ["username",`String "app";"groups",strings []];
                       `O ["username",`String "operator";"groups",strings []]]];
    "clauses",`A clauses;"change_scope",`A (List.map (fun x->`O x) changes)] @
    if version=9 then ["custom_resources",`A [`O ["api_group",`String "acme.example";
      "resource",`String "widgets";"scope",`String "Namespaced";
      "subresources",strings (if narrow then [] else ["status"])]]] else []))
let resource_rule group raw verb names=`O ["apiGroups",strings [group];"resources",strings [raw];
    "verbs",strings [verb];"resourceNames",strings names]
let url_rule paths=`O ["verbs",strings ["get"];"nonResourceURLs",strings paths]
let grant ?(local=false) subject tag rules =
  let metadata=`O (["name",`String tag]@if local then ["namespace",`String "team-a"] else []) in
  let role,binding=if local then "Role","RoleBinding" else "ClusterRole","ClusterRoleBinding" in
  [`O ["apiVersion",`String (api^"/v1");"kind",`String role;"metadata",metadata;"rules",`A rules];
   `O ["apiVersion",`String (api^"/v1");"kind",`String binding;"metadata",metadata;
     "subjects",`A [`O ["kind",`String "User";"apiGroup",`String api;"name",`String subject]];
     "roleRef",`O ["kind",`String role;"apiGroup",`String api;"name",`String tag]]]
let snapshot items=I.json (`O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items])
let common=grant ~local:true "app" "common" [resource_rule "" "configmaps" "get" ["settings"];
    resource_rule "" "namespaces" "get" ["team-a"];resource_rule "" "services" "update" ["web"]]
  @grant "app" "health" [url_rule ["/healthz"]]
let custom_required=grant ~local:true "app" "custom" [resource_rule "acme.example" "widgets" "get" ["required"]]
let forbidden=grant "app" "metrics" [url_rule ["/metrics"]]
let operator_custom=grant ~local:true "operator" "operator-custom" [resource_rule "acme.example" "widgets/status" "patch" ["managed"]]
let operator_url=grant "operator" "operator-url" [url_rule ["/readyz"]]
let baseline=snapshot (common@custom_required@forbidden@operator_custom@operator_url)
let repaired=snapshot (common@custom_required@operator_custom@operator_url)
let regression=snapshot (common@custom_required@operator_url)
let url_regression=snapshot (common@custom_required@operator_custom)
let partial=snapshot (common@operator_custom@operator_url)
let denied=snapshot []
let spec=ok (K.Contract_spec.of_string (contract ()))
let policy source=K.Lower.policy spec (ok (K.Snapshot.of_string source))
let request_of_json principal action path coordinates : Ir.request =
  {principal=Authenticated principal;action;resource=path;context=[];source=0l;host="";scheme="";sni="";
   object_request=(match coordinates with `Null->None|value->Some {namespace=string "namespace" value;
     resource_kind=string "resource_kind" value;name=string "name" value})}
let witness value=request_of_json (string "principal" value) (string "action" value)
  (string "path" value) (field "object_request" value)
let assert_report expected report =
  check "report schema stays10" (field "schema_version" report=`Number "10");
  check "requested verdict" (string "result" report=expected);
  check "coverage profile retained" (string "profile" (field "assurance" report)=profile);
  let frozen=field "frozen_spec" report in
  check "schema9 full catalogue retained in frozen identity"
    (field "schema_version" frozen=`Number "9" && string "canonical" frozen=K.Contract_spec.canonical spec)
let assert_witness ?before after report =
  if string "result" report="violated" then begin
    let ce=field "counterexample" report in let req=witness ce in
    let valid=if string "kind" (field "clause" report)="must_preserve" then
        Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes spec))
          (policy (Option.get before)) (policy after) req
      else Witness.clause (policy after)
        (List.find (fun clause->Contract.name clause=string "name" (field "clause" report))
          (K.Contract_spec.to_contract spec).clauses) req in
    check "typed resource/URL witness validates" valid;
    check "exact source provenance retained" (field "granting_rules" ce=strings (K.Lower.granting_rules (policy after) req));
    check "exact trusted identity groups retained" (field "identity_groups" ce=strings [])
  end
let assert_evidence directory ?before after stdout =
  let manifest=I.parse (read (Filename.concat directory "manifest.json")) in
  let artifact value=let source=read (Filename.concat directory (string "path" value)) in
    check "evidence hashes exact artifact" (Sha256.string source=string "sha256" value);source in
  check "evidence envelope unchanged" (field "schema_version" manifest=`Number (if before=None then "2" else "3"));
  check "evidence exact report" (artifact (field "report" manifest)=stdout);
  check "evidence preserves catalogue and URL contract" (artifact (field "contract" manifest)=K.Contract_spec.canonical spec^"\n");
  let selected=field "assurance_profile" manifest in
  check "evidence profile exact" (string "id" selected=profile &&
    artifact (field "artifact" selected)=K.Assurance.profile_json ~version:9 ()^"\n");
  let bind source value=check "input digest exact" (string "sha256" value=Sha256.string source) in
  (match before with None->bind after (field "config" manifest)
   |Some source->bind source (field "before" (field "inputs" manifest));bind after (field "after" (field "inputs" manifest));
     assert_report "proved" (I.parse (artifact (field "candidate_report" manifest))));
  let clauses=K.Contract_spec.to_contract spec in let plan=Contract_verify.plan (policy after) clauses in
  let entries=array "obligations" manifest in
  check "complete obligation plan retained" (List.length entries=List.length plan+(if before=None then 0 else 1));
  List.iter (fun entry->
    let id=string "id" entry in
    let obligation=List.find_opt (fun (o:Contract_verify.obligation)->o.id=id) plan in
    let expected=match obligation with Some o->o.smtlib|None->
      Smt_encode.decision_equivalence_query ~when_:(Ir.Not (K.Contract_spec.approved_changes spec)) (policy (Option.get before)) (policy after) in
    check "evidence keeps exact frozen-domain query" (artifact (field "query" entry)=expected);
    if field "solver_result" entry=`String "sat" then begin
      let model=field "model" entry in
      let req=request_of_json (string "principal_name" model) (string "method" model)
        (string "path" model) (field "object_request" model) in
      let valid=match obligation with
        |None->Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes spec)) (policy (Option.get before)) (policy after) req
        |Some o->let related=List.map (fun name->List.find (fun c->Contract.name c=name) clauses.clauses) o.clauses in
          if o.phase=Contract_verify.Clause then Witness.clause (policy after) (List.hd related) req
          else Witness.condition ~domain:(policy after).request_domain (Ir.And (List.map Contract.request_class related)) req in
      check "evidence resource/URL SAT model satisfies saved obligation" valid
    end) entries

let mcp_checks directory binary =
  let cp=Filename.concat directory "mcp-contract.json" and bp=Filename.concat directory "mcp-baseline.json" in
  write cp (contract ());write bp baseline;
  with_child directory binary ["mcp";"--connector";"kubernetes-rbac";"--contract";cp;"--baseline";bp] (fun child->
    ignore (field "result" (exchange child 1 "initialize" (`O ["protocolVersion",`String "2024-11-05";
      "capabilities",`O [];"clientInfo",`O ["name",`String "coverage-acceptance";"version",`String "1"]])));
    send child (`O ["jsonrpc",`String "2.0";"method",`String "notifications/initialized"]);
    let tools=array "tools" (field "result" (exchange child 2 "tools/list" (`O []))) in
    check "frozen MCP remains candidate-only" (List.map (string "name") tools=["verify";"compare"]);
    List.iter (fun tool->let schema=field "inputSchema" tool in
      check "MCP schema offers no catalogue override" (field "required" schema=strings ["config"] && field "additionalProperties" schema=`Bool false)) tools;
    let call id operation candidate expected=
      let result=field "result" (exchange child id "tools/call" (`O ["name",`String operation;"arguments",`O ["config",`String candidate]])) in
      let report=field "structuredContent" result in
      check "MCP text matches structured result" (I.parse (string "text" (List.hd (array "content" result)))=report);
      assert_report expected report;assert_witness ?before:(if operation="compare" then Some baseline else None) candidate report in
    write cp (contract ~version:8 ());write bp regression;
    call 3 "verify" baseline "violated";
    call 4 "compare" regression "violated";
    write cp (contract ~narrow:true ());
    call 5 "compare" regression "violated";
    write cp (contract ~extra_changes:[operator_change] ());
    call 6 "compare" regression "violated";
    Sys.remove cp;Sys.remove bp;
    call 7 "compare" repaired "proved";
    call 8 "compare" url_regression "violated";
    let response=exchange child 9 "tools/call" (`O ["name",`String "verify";
      "arguments",`O ["config",`String baseline;"custom_resources",`A [];"request_kind",`String "resource";"contract_version",`Number "8"]]) in
    check "MCP rejects catalogue/classification/downgrade override" (field "code" (field "error" response)=`Number "-32602");
    close_out child.input;
    let ready,_,_=Unix.select [child.output] [] [] 10. in
    check "MCP closes at EOF" (child.pending="" && ready<>[] && Unix.read child.output (Bytes.create 1) 0 1=0);
    let _,status=Unix.waitpid [] child.pid in child.reaped<-true;
    check "MCP has no diagnostics" (status=Unix.WEXITED 0 && read child.error=""))

let gate_checks directory binary helper =
  let workspace=Filename.concat directory "workspace" and action=Filename.concat directory "action"
  and temp=Filename.concat directory "runner-temp" in
  List.iter mkdir [workspace;action;temp];
  List.iter (fun p->mkdir (Filename.concat action p)) ["scripts";"_build";"_build/default";"_build/default/cli"];
  let script=Filename.concat action "scripts/verify-approved-contract.sh" in write script (read helper);
  Unix.symlink (Unix.realpath binary) (Filename.concat action "_build/default/cli/main.exe");
  let git args=let code,out,err=run "git" (["-c";"core.hooksPath=/dev/null";"-C";workspace]@args) in
    check ("fixture git: "^err) (code=0);String.trim out in
  ignore (git ["init";"--quiet"]);
  let cp=Filename.concat workspace "contract.json" and sp=Filename.concat workspace "snapshot.json" in
  write cp (contract ());write sp baseline;
  ignore (git ["add";"--";"contract.json";"snapshot.json"]);
  ignore (git ["-c";"user.name=Soundcheck acceptance";"-c";"user.email=acceptance@example.invalid";
    "-c";"commit.gpgSign=false";"commit";"--quiet";"-m";"Approved static coverage"]);
  let approved=git ["rev-parse";"HEAD"] and event=Filename.concat directory "event.json" in
  write event (I.json (`O ["repository",`O ["full_name",`String "example/soundcheck"];
    "pull_request",`O ["base",`O ["sha",`String approved;"ref",`String "main";
      "repo",`O ["full_name",`String "example/soundcheck"]]]]));
  write cp (contract ~version:8 ());
  let code,out,err=run binary ["rbac";"verify";sp;"--contract";cp;"--format";"json"] in
  check "schema downgrade would hide URL violation" (code=0 && err="" && string "result" (I.parse out)="proved");
  let execute ?(candidate_contract=contract ~version:8 ()) mode candidate expected fragments=
    write sp candidate;write cp candidate_contract;
    let settings=["GITHUB_WORKSPACE",workspace;"GITHUB_EVENT_PATH",event;"GITHUB_EVENT_NAME","pull_request";
      "GITHUB_REPOSITORY","example/soundcheck";"GITHUB_BASE_REF","main";"RUNNER_TEMP",temp;
      "SOUNDCHECK_CONFIG_INPUT","snapshot.json";"SOUNDCHECK_CONTRACT_INPUT","contract.json";
      "SOUNDCHECK_CONNECTOR_INPUT","kubernetes-rbac";"SOUNDCHECK_MODE_INPUT",mode] in
    let inherited=Array.to_list (Unix.environment ()) |> List.filter (fun value->
      not (List.exists (fun (key,_)->String.starts_with ~prefix:(key^"=") value) settings)) in
    let env=Array.of_list (List.map (fun (k,v)->k^"="^v) settings@inherited) in
    let code,out,err=run ~env "bash" [script] in
    check ("schema9 trusted gate: "^err) (code=expected && err="");
    List.iter (fun part->check ("gate retains "^part) (contains out part))
      (["Approved contract: "^approved^":contract.json";profile;"\"schema_version\":9"]@fragments);
    check "gate cleans copies and leaves candidate file" (Sys.readdir temp=[||] && read cp=candidate_contract) in
  execute "verify" baseline 3 ["metrics-forbidden";"/metrics"];
  execute "verify" partial 3 ["custom-required";"widgets"];
  execute "repair" regression 3 ["must_preserve";"widgets/status.acme.example"];
  execute "repair" url_regression 3 ["must_preserve";"/readyz"];
  execute "repair" repaired 0 ["rbac-repair-preservation proved"];
  let original=Filename.concat directory "approved-baseline.json" in write original baseline;
  List.iter (fun weakened->
    write cp weakened;write sp regression;
    let code,out,err=run binary ["rbac";"compare";original;sp;"--contract";cp;"--format";"json"] in
    check "candidate-only metadata weakening would hide preservation loss"
      (code=0 && err="" && string "result" (I.parse out)="proved");
    execute ~candidate_contract:weakened "repair" regression 3 ["must_preserve";"widgets/status.acme.example"])
    [contract ~narrow:true ();contract ~extra_changes:[operator_change] ()]

let evaluator_checks directory evaluator =
  let root=Filename.concat directory "submitted" in mkdir root;let local name=Filename.concat root name in
  write (local "baseline.json") baseline;write (local "contract.json") (contract ());
  write (local "suite.yaml") "format_version: 1\ncases:\n  - id: coverage\n    config: baseline.json\n    contract: contract.json\n    provenance: synthetic\n";
  List.iter (fun (name,source)->write (local (name^".json")) source)
    ["valid",repaired;"partial",partial;"deny-all",denied;"custom-regression",regression;"url-regression",url_regression];
  write (local "submissions.yaml") ("format_version: 1\nattempts:\n"^
    String.concat "" (List.map (fun name->"  - {task: coverage, id: "^name^", config: "^name^".json}\n")
      ["valid";"partial";"deny-all";"custom-regression";"url-regression"]));
  let code,out,err=run evaluator [local "suite.yaml";local "submissions.yaml"] in
  check "submitted evaluator runs schema9 task" (code=0 && err="");
  let summary=I.parse out in
  check "submitted schema/profile stable" (field "experimental_format_version" summary=`Number "2" && string "profile" summary=profile);
  let task=List.hd (array "tasks" summary) in
  check "submitted task retains frozen catalogue digest" (string "frozen_contract_sha256" task=Sha256.string (K.Contract_spec.canonical spec));
  let attempts=array "attempts" task in
  List.iter (fun (id,result)->let row=List.find (fun x->string "id" x=id) attempts in
    check ("submitted result "^id) (string "repair_result" row=result))
    ["valid","valid_repair";"partial","contract_failed";"deny-all","contract_failed";
     "custom-regression","out_of_scope_regression";"url-regression","out_of_scope_regression"];
  write (local "submissions.yaml") "format_version: 1\nattempts:\n  - {task: coverage, id: bad, config: valid.json, custom_resources: [], contract_version: 8}\n";
  let code,out,err=run evaluator [local "suite.yaml";local "submissions.yaml"] in
  check "submitted metadata cannot replace catalogue" (code=1 && err="" && string "failure" (List.hd (array "tasks" (I.parse out)))="submissions_invalid")

let () =
  if Array.length Sys.argv<>4 then failwith "expected CLI, approved-contract helper and submitted-repair evaluator";
  let binary=Sys.argv.(1) and helper=Sys.argv.(2) and evaluator=Sys.argv.(3) in
  let directory=temporary_directory () in
  Fun.protect ~finally:(fun ()->cleanup directory) (fun ()->
    let code,out,err=run binary ["profile";"kubernetes-rbac";"--contract-version";"9";"--format";"json"] in
    check "CLI selects schema9 profile" (code=0 && err="");
    let selected=I.parse out in
    check "CLI profile exact public versions" (string "id" selected=profile && field "schema_version" selected=`Number "6" && field "contract_schema_version" selected=`Number "9");
    let cp=Filename.concat directory "contract.json" and bp=Filename.concat directory "baseline.json" in
    write cp (contract ());write bp baseline;
    let code,out,err=run binary ["rbac";"check-contract";cp] in
    check "review exposes frozen custom and URL intent"
      (code=0 && err="" && contains out "Contract schema: 9" && contains out "structure only" && contains out "widgets" && contains out "/metrics");
    let invoke ?before ?(evidence=false) tag candidate expected=
      let path=Filename.concat directory (tag^".json") and evidence_path=Filename.concat directory (tag^"-evidence") in
      write path candidate;
      let operation=match before with None->["verify";path]|Some _->["compare";bp;path] in
      let code,out,err=run binary ("rbac"::operation@["--contract";cp;"--format";"json"]@
        if evidence then ["--evidence-dir";evidence_path] else []) in
      check ("CLI "^tag^": "^err) (code=(if expected="proved" then 0 else 3) && err="");
      let report=I.parse out in assert_report expected report;assert_witness ?before candidate report;
      if evidence then assert_evidence evidence_path ?before candidate out;report in
    let r=invoke ~evidence:true "unsafe-url" baseline "violated" in
    check "URL counterexample preserves disjoint shape"
      (field "object_request" (field "counterexample" r)=`Null && string "path" (field "counterexample" r)="/metrics");
    ignore (invoke ~evidence:true "partial" partial "violated");
    ignore (invoke "deny-all" denied "violated");
    ignore (invoke ~before:baseline ~evidence:true "valid" repaired "proved");
    let r=invoke ~before:baseline ~evidence:true "custom-regression" regression "violated" in
    check "unmentioned custom identity preserved" (string "principal" (field "counterexample" r)="operator");
    let r=invoke ~before:baseline ~evidence:true "url-regression" url_regression "violated" in
    check "unmentioned URL identity preserved" (string "principal" (field "counterexample" r)="operator" && field "object_request" (field "counterexample" r)=`Null);
    mcp_checks directory binary;
    gate_checks directory binary helper;
    evaluator_checks directory evaluator);
  Printf.printf "RBAC coverage adapters: %d checks passed\n" !checks
