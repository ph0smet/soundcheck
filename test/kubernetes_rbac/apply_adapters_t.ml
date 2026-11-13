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
  let path=Filename.temp_file "soundcheck-rbac-apply-adapters-" "" in
  Unix.unlink path;mkdir path;Unix.realpath path
let run ?env binary args =
  let output=Filename.temp_file "rbac-apply-out-" "" and error=Filename.temp_file "rbac-apply-err-" "" in
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

let profile="kubernetes-rbac-v1.34-apply-v1"
let api="rbac.authorization.k8s.io"
let scope ?(subject="app") ?(operation="apply-missing") ?(group="apps") ?(resource="deployments")
    ?(subresource="") ?(ns=`String "team-a") ?(names=strings ["web"]) () =
  ["subject",`String subject;"operation",`String operation;"api_group",`String group;
   "resource",`String resource;"subresource",`String subresource;"namespace",ns;"names",names]
let operator_change=scope ~subject:"operator" ~group:"" ~resource:"nodes" ~ns:`Null ~names:(strings ["node-a"]) ()
let contract ?(version=8) ?(required_operation="apply-missing") ?(extra_changes=[]) () =
  let required,forbidden,changes=if version=8 then
    scope ~operation:required_operation (),
    scope ~group:"" ~resource:"configmaps" ~names:(strings ["blocked"]) (),
    [scope ~group:"" ~resource:"configmaps" ~names:(strings ["blocked"]) ()]
    else scope ~operation:"patch" (),scope ~operation:"get" ~group:"" ~resource:"secrets" ~names:`Null (),[] in
  let fields xs=if version>=8 then xs else
    ("verb",List.assoc "operation" xs)::List.remove_assoc "operation" xs in
  I.json (`O ["schema_version",`Number (string_of_int version);"kind",`String "kubernetes-rbac-access";
    "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
      "identities",`A [`O ["username",`String "app";"groups",strings []];
                       `O ["username",`String "operator";"groups",strings []]]];
    "clauses",`A [
      `O (["name",`String "deployment-apply-required";"kind",`String "must_allow"] @ fields required);
      `O (["name",`String "configmap-apply-forbidden";"kind",`String "must_not_grant"] @ fields forbidden)];
    "change_scope",`A (List.map (fun xs -> `O (fields xs)) (changes@extra_changes))])
let grant ?(local=false) subject tag group resource verb names =
  let metadata=`O (["name",`String tag] @ if local then ["namespace",`String "team-a"] else []) in
  let role,binding=if local then "Role","RoleBinding" else "ClusterRole","ClusterRoleBinding" in
  [`O ["apiVersion",`String (api^"/v1");"kind",`String role;"metadata",metadata;
     "rules",`A [`O ["apiGroups",strings [group];"resources",strings [resource];
       "verbs",strings [verb];"resourceNames",strings names]]];
   `O ["apiVersion",`String (api^"/v1");"kind",`String binding;"metadata",metadata;
     "subjects",`A [`O ["kind",`String "User";"apiGroup",`String api;"name",`String subject]];
     "roleRef",`O ["kind",`String role;"apiGroup",`String api;"name",`String tag]]]
let snapshot items=I.json (`O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items])
let required_patch=grant ~local:true "app" "required-patch" "apps" "deployments" "patch" ["web"]
let required_create=grant ~local:true "app" "required-create" "apps" "deployments" "create" ["web"]
let forbidden_patch=grant ~local:true "app" "forbidden-patch" "" "configmaps" "patch" ["blocked"]
let forbidden_create=grant ~local:true "app" "forbidden-create" "" "configmaps" "create" ["blocked"]
let operator_patch=grant "operator" "operator-patch" "" "nodes" "patch" ["node-a"]
let operator_create=grant "operator" "operator-create" "" "nodes" "create" ["node-a"]
let baseline=snapshot (required_patch@required_create@forbidden_patch@forbidden_create@operator_patch@operator_create)
let repaired=snapshot (required_patch@required_create@forbidden_patch@operator_patch@operator_create)
let regression=snapshot (required_patch@required_create@forbidden_patch@operator_patch)
let partial=snapshot (required_patch@forbidden_patch@operator_patch@operator_create)
let denied=snapshot []
let spec=ok (K.Contract_spec.of_string (contract ()))
let policy source=K.Lower.policy spec (ok (K.Snapshot.of_string source))
let request_of_json principal action coordinates : Ir.request =
  {principal=Authenticated principal;action;resource="";context=[];source=0l;host="";scheme="";sni="";
   object_request=Some {namespace=string "namespace" coordinates;resource_kind=string "resource_kind" coordinates;
     name=string "name" coordinates}}
let witness_request value=request_of_json (string "principal" value) (string "action" value) (field "object_request" value)
let assert_report expected report =
  check "unchanged report envelope" (field "schema_version" report=`Number "10");
  check "requested verdict" (string "result" report=expected);
  check "versioned apply assurance" (string "profile" (field "assurance" report)=profile);
  let frozen=field "frozen_spec" report in
  check "v8 frozen version and exact canonical contract"
    (field "schema_version" frozen=`Number "8" && string "canonical" frozen=K.Contract_spec.canonical spec)
let assert_witness ?before after report =
  if string "result" report="violated" then begin
    let value=field "counterexample" report in
    let request=witness_request value in
    let valid=if string "kind" (field "clause" report)="must_preserve" then
        Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes spec))
          (policy (Option.get before)) (policy after) request
      else Witness.clause (policy after)
        (List.find (fun clause -> Contract.name clause=string "name" (field "clause" report))
          (K.Contract_spec.to_contract spec).clauses) request in
    check "adapter witness satisfies the compound obligation" valid;
    check "stage-qualified provenance survives adapters"
      (field "granting_rules" value=strings (K.Lower.granting_rules (policy after) request));
    check "exact trusted groups survive adapters" (field "identity_groups" value=strings []);
    let c=Option.get request.object_request in
    check "apply witness retains operation and named URL target"
      (request.action="apply-missing" && c.name<>"");
    let group,raw=match c.resource_kind with
      | "deployments.apps" -> "apps","deployments"
      | "nodes" -> "","nodes"
      | "configmaps" -> "","configmaps"
      | _ -> failwith ("unexpected fixture witness kind: "^c.resource_kind) in
    let input=I.json (`A [`O ["id",`String "lifted";"username",`String (string "principal" value);
      "groups",strings [];"operation",`String request.action;"apiGroup",`String group;"resource",`String raw;
      "namespace",`String c.namespace;"name",`String c.name;"subresource",`String "";"resourceRequest",`Bool true]]) in
    let rows=ok (K.Evaluate.requests spec input) in
    check "compound witness round-trips through concrete operation input" ((List.hd rows).request=request);
    let decision=List.hd (I.arr "decisions" (K.Evaluate.decisions (policy after) rows)) in
    check "concrete decision agrees with aggregate operation"
      (string "decision" decision=(if Ir.possibly_allows (policy after) request then "Allow" else "NoOpinion"));
    check "Evaluate keeps exact stage-qualified grants" (field "grants" decision=field "granting_rules" value)
  end
let assert_evidence directory ?before after stdout =
  let manifest=I.parse (read (Filename.concat directory "manifest.json")) in
  let artifact value=let bytes=read (Filename.concat directory (string "path" value)) in
    check "evidence artifact hashes exact bytes" (Sha256.string bytes=string "sha256" value);bytes in
  check "evidence envelope unchanged" (field "schema_version" manifest=`Number (if before=None then "2" else "3"));
  check "evidence preserves exact result" (artifact (field "report" manifest)=stdout);
  check "evidence binds operation-aware frozen artifact" (artifact (field "contract" manifest)=K.Contract_spec.canonical spec^"\n");
  let selected=field "assurance_profile" manifest in
  check "evidence names apply profile" (string "id" selected=profile);
  check "evidence saves exact apply profile" (artifact (field "artifact" selected)=K.Assurance.profile_json ~version:8 ()^"\n");
  let bind source value=check "evidence binds exact policy bytes"
    (string "sha256" value=Sha256.string source && field "size_bytes" value=`Number (string_of_int (String.length source))) in
  (match before with None -> bind after (field "config" manifest)
   | Some source -> bind source (field "before" (field "inputs" manifest));
     bind after (field "after" (field "inputs" manifest));
     assert_report "proved" (I.parse (artifact (field "candidate_report" manifest))));
  let clauses=K.Contract_spec.to_contract spec in
  let plan=Contract_verify.plan (policy after) clauses in
  let entries=array "obligations" manifest in
  check "evidence keeps full obligation plan"
    (string "status" (field "obligation_plan" manifest)="complete" &&
     List.length entries=List.length plan+(if before=None then 0 else 1));
  List.iter (fun entry ->
    let id=string "id" entry in
    let obligation=List.find_opt (fun (o:Contract_verify.obligation) -> o.id=id) plan in
    let expected=match obligation with Some o -> o.smtlib | None ->
      Smt_encode.decision_equivalence_query ~when_:(Ir.Not (K.Contract_spec.approved_changes spec))
        (policy (Option.get before)) (policy after) in
    check "saved query retains both hypothetical branches" (artifact (field "query" entry)=expected);
    if field "solver_result" entry=`String "sat" then begin
      let model=field "model" entry in
      let request=request_of_json (string "principal_name" model) (string "method" model) (field "object_request" model) in
      let valid=match obligation with
        | None -> Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes spec))
          (policy (Option.get before)) (policy after) request
        | Some o ->
          let related=List.map (fun name -> List.find (fun c -> Contract.name c=name) clauses.clauses) o.clauses in
          if o.phase=Contract_verify.Clause then Witness.clause (policy after) (List.hd related) request
          else Witness.condition ~domain:(policy after).request_domain (Ir.And (List.map Contract.request_class related)) request in
      check "saved model validates against its saved obligation" valid
    end) entries

let mcp_checks directory binary =
  let contract_path=Filename.concat directory "mcp-contract.json" and baseline_path=Filename.concat directory "mcp-baseline.json" in
  write contract_path (contract ());write baseline_path baseline;
  with_child directory binary ["mcp";"--connector";"kubernetes-rbac";"--contract";contract_path;"--baseline";baseline_path] (fun child ->
    ignore (field "result" (exchange child 1 "initialize" (`O ["protocolVersion",`String "2024-11-05";
      "capabilities",`O [];"clientInfo",`O ["name",`String "apply-acceptance";"version",`String "1"]])));
    send child (`O ["jsonrpc",`String "2.0";"method",`String "notifications/initialized"]);
    let tools=array "tools" (field "result" (exchange child 2 "tools/list" (`O []))) in
    check "v8 tools retain candidate-only interface" (List.map (string "name") tools=["verify";"compare"]);
    List.iter (fun tool -> let schema=field "inputSchema" tool in
      check "MCP permits no scope overrides" (field "required" schema=strings ["config"] && field "additionalProperties" schema=`Bool false)) tools;
    write contract_path (contract ~version:7 ());write baseline_path regression;
    let call id operation candidate expected =
      let result=field "result" (exchange child id "tools/call" (`O ["name",`String operation;
        "arguments",`O ["config",`String candidate]])) in
      let report=field "structuredContent" result in
      check "MCP text equals structured report" (I.parse (string "text" (List.hd (array "content" result)))=report);
      assert_report expected report;
      assert_witness ?before:(if operation="compare" then Some baseline else None) candidate report in
    call 3 "verify" partial "violated";
    call 4 "compare" regression "violated";
    write contract_path (contract ~extra_changes:[operator_change] ());
    call 5 "compare" regression "violated";
    Sys.remove contract_path;Sys.remove baseline_path;
    call 6 "verify" repaired "proved";call 7 "compare" repaired "proved";
    let response=exchange child 8 "tools/call" (`O ["name",`String "verify";
      "arguments",`O ["config",`String partial;"operation",`String "patch";
        "contract_version",`Number "7";"object_state",`String "existing"]]) in
    check "MCP rejects operation, hypothetical state and schema substitution"
      (field "code" (field "error" response)=`Number "-32602");
    close_out child.input;
    let ready,_,_=Unix.select [child.output] [] [] 10. in
    check "MCP closes cleanly at EOF" (child.pending="" && ready<>[] && Unix.read child.output (Bytes.create 1) 0 1=0);
    let _,status=Unix.waitpid [] child.pid in child.reaped<-true;
    check "MCP operation session has no diagnostics" (status=Unix.WEXITED 0 && read child.error=""))

let gate_checks directory binary helper =
  let workspace=Filename.concat directory "workspace" and action=Filename.concat directory "action"
  and runner_temp=Filename.concat directory "runner-temp" in
  List.iter mkdir [workspace;action;runner_temp];
  List.iter (fun name -> mkdir (Filename.concat action name)) ["scripts";"_build"];
  mkdir (Filename.concat action "_build/default");mkdir (Filename.concat action "_build/default/cli");
  let script=Filename.concat action "scripts/verify-approved-contract.sh" in write script (read helper);
  Unix.symlink (Unix.realpath binary) (Filename.concat action "_build/default/cli/main.exe");
  let git args=let code,stdout,stderr=run "git" (["-c";"core.hooksPath=/dev/null";"-C";workspace] @ args) in
    check ("local gate git: "^stderr) (code=0);String.trim stdout in
  ignore (git ["init";"--quiet"]);
  let config_path=Filename.concat workspace "snapshot.json" and contract_path=Filename.concat workspace "contract.json" in
  write config_path baseline;write contract_path (contract ());
  ignore (git ["add";"--";"snapshot.json";"contract.json"]);
  ignore (git ["-c";"user.name=Soundcheck acceptance";"-c";"user.email=acceptance@example.invalid";
    "-c";"commit.gpgSign=false";"commit";"--quiet";"-m";"Approved apply contract"]);
  let approved=git ["rev-parse";"HEAD"] and event=Filename.concat directory "event.json" in
  write event (I.json (`O ["repository",`O ["full_name",`String "example/soundcheck"];
    "pull_request",`O ["base",`O ["sha",`String approved;"ref",`String "main";
      "repo",`O ["full_name",`String "example/soundcheck"]]]]));
  let weakened=contract ~version:7 () in write contract_path weakened;
  let code,stdout,stderr=run binary ["rbac";"verify";config_path;"--contract";contract_path;"--format";"json"] in
  check "candidate schema downgrade would hide the apply violation"
    (code=0 && stderr="" && string "result" (I.parse stdout)="proved");
  let execute ?(candidate_contract=weakened) mode candidate expected fragments =
    write config_path candidate;write contract_path candidate_contract;
    let settings=["GITHUB_WORKSPACE",workspace;"GITHUB_EVENT_PATH",event;"GITHUB_EVENT_NAME","pull_request";
      "GITHUB_REPOSITORY","example/soundcheck";"GITHUB_BASE_REF","main";"RUNNER_TEMP",runner_temp;
      "SOUNDCHECK_CONFIG_INPUT","snapshot.json";"SOUNDCHECK_CONTRACT_INPUT","contract.json";
      "SOUNDCHECK_CONNECTOR_INPUT","kubernetes-rbac";"SOUNDCHECK_MODE_INPUT",mode] in
    let inherited=Array.to_list (Unix.environment ()) |> List.filter (fun value ->
      not (List.exists (fun (key,_) -> String.starts_with ~prefix:(key^"=") value) settings)) in
    let env=Array.of_list (List.map (fun (key,value) -> key^"="^value) settings @ inherited) in
    let code,stdout,stderr=run ~env "bash" [script] in
    check ("approved v8 gate: "^stderr) (code=expected && stderr="");
    List.iter (fun part -> check ("gate output includes "^part) (contains stdout part))
      (["Approved contract: "^approved^":contract.json";profile;"\"schema_version\":8"] @ fragments);
    check "gate cleans frozen copies and leaves candidate contract alone"
      (Sys.readdir runner_temp=[||] && read contract_path=candidate_contract) in
  execute "verify" baseline 3 ["configmap-apply-forbidden";"apply-missing";"configmaps"];
  execute "verify" partial 3 ["deployment-apply-required";"apply-missing"];
  execute "repair" regression 3 ["Approved baseline: "^approved^":snapshot.json";"must_preserve";"nodes";"apply-missing"];
  execute "repair" repaired 0 ["rbac-repair-preservation proved"];
  let expanded=contract ~extra_changes:[operator_change] () in
  let original=Filename.concat directory "original-gate-baseline.json" in
  write original baseline;write config_path regression;write contract_path expanded;
  let code,stdout,stderr=run binary ["rbac";"compare";original;config_path;
    "--contract";contract_path;"--format";"json"] in
  check "candidate scope widening would hide the missing-object preservation regression"
    (code=0 && stderr="" && string "result" (I.parse stdout)="proved");
  execute ~candidate_contract:expanded "repair" regression 3
    ["Approved baseline: "^approved^":snapshot.json";"must_preserve";"nodes";"apply-missing"]

let evaluator_checks directory evaluator =
  let root=Filename.concat directory "submitted" in mkdir root;
  let local name=Filename.concat root name in
  write (local "baseline.json") baseline;write (local "contract.json") (contract ());
  write (local "suite.yaml") "format_version: 1\ncases:\n  - id: apply\n    config: baseline.json\n    contract: contract.json\n    provenance: synthetic\n";
  List.iter (fun (name,source) -> write (local (name^".json")) source)
    ["valid",repaired;"partial",partial;"deny-all",denied;"regression",regression];
  write (local "submissions.yaml") ("format_version: 1\nattempts:\n"^
    String.concat "" (List.map (fun name -> "  - {task: apply, id: "^name^", config: "^name^".json}\n")
      ["valid";"partial";"deny-all";"regression"]));
  let code,stdout,stderr=run evaluator [local "suite.yaml";local "submissions.yaml"] in
  check "actual submitted evaluator accepts the task with one valid repair" (code=0 && stderr="");
  let summary=I.parse stdout in
  check "submitted format stable and selected profile exact"
    (field "experimental_format_version" summary=`Number "2" && string "profile" summary=profile);
  let task=List.hd (array "tasks" summary) in
  check "submitted benchmark binds frozen operation contract"
    (string "frozen_contract_sha256" task=Sha256.string (K.Contract_spec.canonical spec));
  let attempts=array "attempts" task in
  List.iter (fun (id,result) -> let row=List.find (fun row -> string "id" row=id) attempts in
    check ("submitted classification "^id) (string "repair_result" row=result))
    ["valid","valid_repair";"partial","contract_failed";"deny-all","contract_failed";"regression","out_of_scope_regression"];
  check "benchmark summary excludes raw witness details" (not (contains stdout "node-a"));
  write (local "submissions.yaml") "format_version: 1\nattempts:\n  - {task: apply, id: bad, config: partial.json, operation: patch, object_state: existing, contract_version: 7}\n";
  let code,stdout,stderr=run evaluator [local "suite.yaml";local "submissions.yaml"] in
  check "submitted metadata cannot downgrade the frozen operation"
    (code=1 && stderr="" && string "failure" (List.hd (array "tasks" (I.parse stdout)))="submissions_invalid")

let profile_checks binary =
  let code,stdout,stderr=run binary ["profile";"kubernetes-rbac";"--contract-version";"8";"--format";"json"] in
  check "CLI selects explicit apply profile" (code=0 && stderr="");
  let value=I.parse stdout in
  check "profile schema5 and contract schema8"
    (string "id" value=profile && field "schema_version" value=`Number "5"
     && field "contract_schema_version" value=`Number "8");
  check "profile does not publish an accidental Cartesian verb product"
    (match value with `O fields -> not (List.mem_assoc "verbs" fields || List.mem_assoc "subresource" fields) | _ -> false);
  let operation op checks state names ns=op,checks,state,names,ns in
  let base_operations cluster=List.map (fun op ->
    let collection=List.mem op ["create";"deletecollection"] and read=List.mem op ["list";"watch"] in
    operation op [op] `Null (if collection then "empty" else if read then "empty-or-named" else "named")
      (if cluster then "empty" else if read then "empty-or-named" else "named"))
    ["get";"list";"watch";"update";"patch";"delete";"create";"deletecollection"] @
    [operation "apply-existing" ["patch"] (`String "existing") "named" (if cluster then "empty" else "named");
     operation "apply-missing" ["patch";"create"] (`String "missing") "named" (if cluster then "empty" else "named")] in
  let bases=["","configmaps","configmaps",false;"","secrets","secrets",false;
    "","pods","pods",false;"","services","services",false;"","endpoints","endpoints",false;
    "","nodes","nodes",true;"apps","deployments","deployments.apps",false;
    "discovery.k8s.io","endpointslices","endpointslices.discovery.k8s.io",false] in
  let subs=["","pods","log","pods/log",false,["get"];
    "","pods","exec","pods/exec",false,["get";"create"];
    "","serviceaccounts","token","serviceaccounts/token",false,["create"];
    "","pods","status","pods/status",false,["get";"update";"patch"];
    "","services","status","services/status",false,["get";"update";"patch"];
    "","nodes","status","nodes/status",true,["get";"update";"patch"];
    "apps","deployments","status","deployments/status.apps",false,["get";"update";"patch"];
    "apps","deployments","scale","deployments/scale.apps",false,["get";"update";"patch"]] in
  let expected=(List.map (fun (group,raw,kind,cluster) ->
    group,raw,"",(if cluster then "cluster" else "namespaced"),kind,base_operations cluster) bases) @
    List.map (fun (group,raw,sub,kind,cluster,ops) -> group,raw,sub,
      (if cluster then "cluster" else "namespaced"),kind,
      List.map (fun op -> operation op [op] `Null "named" (if cluster then "empty" else "named")) ops) subs in
  let normalize (group,raw,sub,scope,kind,ops)=group,raw,sub,scope,kind,List.sort compare ops in
  let actual=array "resource_domains" value |> List.map (fun r -> normalize
    (string "api_group" r,string "resource" r,string "subresource" r,string "scope" r,
     string "resource_kind" r,List.map (fun op ->
       string "operation" op,List.map (I.str "check") (array "checks" op),field "object_state" op,
       string "name_domain" op,string "namespace_domain" op) (array "operations" r))) in
  check "profile publishes exact old operations plus sixteen apply branches"
    (List.sort compare actual=List.sort compare (List.map normalize expected));
  let code,human,stderr=run binary ["profile";"kubernetes-rbac";"--contract-version";"8"] in
  check "human profile describes operation stages and hypothetical branches"
    (code=0 && stderr="" && contains human profile && contains human "apply-existing"
     && contains human "apply-missing" && contains human "patch" && contains human "create")

let () =
  if Array.length Sys.argv<>4 then failwith "expected CLI, approved-contract helper and submitted-repair evaluator";
  let binary=Sys.argv.(1) and helper=Sys.argv.(2) and evaluator=Sys.argv.(3) in
  let directory=temporary_directory () in
  Fun.protect ~finally:(fun () -> cleanup directory) (fun () ->
    profile_checks binary;
    let contract_path=Filename.concat directory "contract.json" and baseline_path=Filename.concat directory "baseline.json" in
    write contract_path (contract ());write baseline_path baseline;
    let code,stdout,stderr=run binary ["rbac";"check-contract";contract_path] in
    check "authoring review identifies apply branch and checks without proving access"
      (code=0 && stderr="" && contains stdout "Contract schema: 8" && contains stdout "apply-missing"
       && contains stdout "patch" && contains stdout "create" && contains stdout "structure only");
    let invoke ?before ?(evidence=false) tag candidate expected =
      let path=Filename.concat directory (tag^".json") and evidence_path=Filename.concat directory (tag^"-evidence") in
      write path candidate;
      let operation=match before with None -> ["verify";path] | Some _ -> ["compare";baseline_path;path] in
      let code,stdout,stderr=run binary ("rbac"::operation @ ["--contract";contract_path;"--format";"json"] @
        if evidence then ["--evidence-dir";evidence_path] else []) in
      check ("CLI "^tag^": "^stderr) (code=(if expected="proved" then 0 else 3) && stderr="");
      let report=I.parse stdout in assert_report expected report;assert_witness ?before candidate report;
      if evidence then assert_evidence evidence_path ?before candidate stdout;
      report in
    let missing=invoke ~evidence:true "partial" partial "violated" in
    let ce=field "counterexample" missing in
    check "partial apply preserves operation and omits successful grants"
      (string "action" ce="apply-missing" && field "granting_rules" ce=`A []
       && string "name" (field "object_request" ce)="web");
    let unsafe=invoke "forbidden" baseline "violated" in
    let grants=List.map (I.str "grant") (array "granting_rules" (field "counterexample" unsafe)) in
    check "successful forbidden apply reports sources for both stages"
      (List.exists (String.starts_with ~prefix:"patch: ") grants && List.exists (String.starts_with ~prefix:"create: ") grants);
    ignore (invoke "deny-all" denied "violated");
    ignore (invoke ~before:baseline ~evidence:true "valid" repaired "proved");
    let changed=invoke ~before:baseline ~evidence:true "operator-regression" regression "violated" in
    check "preservation includes unmentioned cluster resource and identity"
      (string "resource_kind" (field "object_request" (field "counterexample" changed))="nodes"
       && string "principal" (field "counterexample" changed)="operator"
       && string "action" (field "counterexample" changed)="apply-missing"
       && string "namespace" (field "object_request" (field "counterexample" changed))="");
    let path=Filename.concat directory "partial.json" in
    let code,human,stderr=run binary ["rbac";"verify";path;"--contract";contract_path] in
    check "human report explains missing stage of apply"
      (code=3 && stderr="" && contains human "apply-missing" && contains human "create" && contains human "web");
    let invalid=Filename.concat directory "invalid-contract.json" in
    let value=I.parse (contract ()) in
    let bad=match value with `O fields ->
      let clauses=match field "clauses" value with `A (`O first::rest) ->
        `A (`O (("verb",`String "patch")::first)::rest) | _ -> assert false in
      `O (("clauses",clauses)::List.remove_assoc "clauses" fields) | _ -> assert false in
    write invalid (I.json bad);
    let code,stdout,stderr=run binary ["rbac";"check-contract";invalid] in
    check "authoring rejects mixed native verb and operation fields"
      (code=2 && not (contains stdout "proved") && contains stderr "verb");
    mcp_checks directory binary;
    gate_checks directory binary helper;
    evaluator_checks directory evaluator);
  Printf.printf "RBAC apply adapters: %d checks passed\n" !checks
