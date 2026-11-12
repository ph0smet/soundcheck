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
  let path=Filename.temp_file "soundcheck-rbac-collection-write-adapters-" "" in
  Unix.unlink path;mkdir path;Unix.realpath path
let run ?env binary args =
  let output=Filename.temp_file "rbac-collection-write-out-" "" and error=Filename.temp_file "rbac-collection-write-err-" "" in
  Fun.protect ~finally:(fun () -> List.iter Sys.remove [output;error]) (fun () ->
    let out=Unix.openfile output [Unix.O_WRONLY;Unix.O_TRUNC] 0o600
    and err=Unix.openfile error [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let argv=Array.of_list (binary::args) in
    let pid=match env with None -> Unix.create_process binary argv Unix.stdin out err
      | Some env -> Unix.create_process_env binary argv env Unix.stdin out err in
    Unix.close out;Unix.close err;
    let _,status=Unix.waitpid [] pid in
    (match status with Unix.WEXITED code -> code | _ -> failwith "child terminated"),read output,read error)
let profile="kubernetes-rbac-v1.34-collection-write-v1"
let api="rbac.authorization.k8s.io"
let scope ?(subject="app") ?(verb="get") ?(group="") ?(resource="configmaps")
    ?(ns=`String "team-a") ?(names=strings ["settings"]) () =
  ["subject",`String subject;"verb",`String verb;"api_group",`String group;
    "resource",`String resource;"namespace",ns;"names",names]
let contract ?(version=6) () =
  let required,forbidden,changes=if version=6 then
    scope ~verb:"create" ~group:"apps" ~resource:"deployments" ~names:(`O ["empty",`Bool true]) (),
    scope ~verb:"deletecollection" ~resource:"pods" ~names:`Null (),
    [scope ~verb:"deletecollection" ~resource:"pods" ~names:`Null ()]
    else scope (),scope ~resource:"secrets" ~names:`Null (),[] in
  let fields xs=if version>=5 then xs else List.remove_assoc "api_group" xs in
  I.json (`O ["schema_version",`Number (string_of_int version);"kind",`String "kubernetes-rbac-access";
    "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
      "identities",`A [`O ["username",`String "app";"groups",strings []];
                       `O ["username",`String "operator";"groups",strings []]]];
    "clauses",`A [
      `O (["name",`String "deployment-create-required";"kind",`String "must_allow"] @ fields required);
      `O (["name",`String "pod-bulk-delete-forbidden";"kind",`String "must_not_grant"] @ fields forbidden)];
    "change_scope",`A (List.map (fun xs -> `O (fields xs)) changes)])
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
let core=grant ~local:true "app" "config" "" "configmaps" "get" ["settings"]
let workload=grant ~local:true "app" "deployment" "apps" "deployments" "create" []
let monitor=grant "operator" "monitor" "" "nodes" "create" []
let bulk=grant ~local:true "app" "bulk" "" "pods" "deletecollection" []
let baseline=snapshot (core @ workload @ monitor @ bulk)
let repaired=snapshot (core @ workload @ monitor @ [List.hd bulk])
let regression=snapshot (core @ workload @ [List.hd monitor;List.hd bulk])
let denied=snapshot core
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
  check "versioned collection-write assurance" (string "profile" (field "assurance" report)=profile);
  let frozen=field "frozen_spec" report in
  check "v6 frozen version and exact canonical contract"
    (field "schema_version" frozen=`Number "6" && string "canonical" frozen=K.Contract_spec.canonical spec)
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
    check "adapter witness satisfies actual obligation" valid;
    check "grouped grant provenance survives adapters"
      (field "granting_rules" value=strings (K.Lower.granting_rules (policy after) request));
    check "exact trusted groups survive adapters" (field "identity_groups" value=strings []);
    (* Independent decoder for the two qualified kinds in this approved profile.
       Do not guess a group by splitting arbitrary dotted strings. *)
    let c=Option.get request.object_request in
    check "new operation witnesses never fabricate body or deletion-target names"
      (c.name="" && List.mem request.action ["create";"deletecollection"]);
    let group,raw=match c.resource_kind with
      | "deployments.apps" -> "apps","deployments"
      | "endpointslices.discovery.k8s.io" -> "discovery.k8s.io","endpointslices"
      | "nodes" -> "","nodes"
      | "pods" -> "","pods"
      | _ -> failwith ("unexpected fixture witness kind: "^c.resource_kind) in
    let input=I.json (`A [`O ["id",`String "lifted";"username",`String (string "principal" value);
      "groups",strings [];"verb",`String request.action;"apiGroup",`String group;"resource",`String raw;
      "namespace",`String c.namespace;"name",`String c.name;"subresource",`String "";"resourceRequest",`Bool true]]) in
    check "qualified witness round-trips to concrete request"
      ((List.hd (ok (K.Evaluate.requests spec input))).request=request)
  end
let assert_evidence directory ?before after stdout =
  let manifest=I.parse (read (Filename.concat directory "manifest.json")) in
  let artifact value=let bytes=read (Filename.concat directory (string "path" value)) in
    check "evidence artifact hashes exact bytes" (Sha256.string bytes=string "sha256" value);bytes in
  check "evidence envelope unchanged" (field "schema_version" manifest=`Number (if before=None then "2" else "3"));
  check "evidence preserves exact result" (artifact (field "report" manifest)=stdout);
  check "evidence binds new frozen artifact" (artifact (field "contract" manifest)=K.Contract_spec.canonical spec^"\n");
  let selected=field "assurance_profile" manifest in
  check "evidence names resource profile" (string "id" selected=profile);
  check "evidence saves exact resource profile" (artifact (field "artifact" selected)=K.Assurance.profile_json ~version:6 ()^"\n");
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
    check "saved query retains the precise catalogue and obligation" (artifact (field "query" entry)=expected);
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
let mcp_checks directory binary =
  let contract_path=Filename.concat directory "mcp-contract.json" and baseline_path=Filename.concat directory "mcp-baseline.json" in
  write contract_path (contract ());write baseline_path baseline;
  with_child directory binary ["mcp";"--connector";"kubernetes-rbac";"--contract";contract_path;"--baseline";baseline_path] (fun child ->
    ignore (field "result" (exchange child 1 "initialize" (`O ["protocolVersion",`String "2024-11-05";
      "capabilities",`O [];"clientInfo",`O ["name",`String "collection-write-acceptance";"version",`String "1"]])));
    send child (`O ["jsonrpc",`String "2.0";"method",`String "notifications/initialized"]);
    let tools=array "tools" (field "result" (exchange child 2 "tools/list" (`O []))) in
    check "v6 tools retain config-only interface" (List.map (string "name") tools=["verify";"compare"]);
    List.iter (fun tool -> let schema=field "inputSchema" tool in
      check "MCP permits no scope overrides" (field "required" schema=strings ["config"] && field "additionalProperties" schema=`Bool false)) tools;
    write contract_path (contract ~version:5 ());write baseline_path regression;
    let call id operation candidate expected =
      let result=field "result" (exchange child id "tools/call" (`O ["name",`String operation;
        "arguments",`O ["config",`String candidate]])) in
      let report=field "structuredContent" result in
      check "MCP text equals structured report" (I.parse (string "text" (List.hd (array "content" result)))=report);
      assert_report expected report;
      assert_witness ?before:(if operation="compare" then Some baseline else None) candidate report in
    call 3 "verify" baseline "violated";
    call 4 "compare" regression "violated";
    Sys.remove contract_path;Sys.remove baseline_path;
    call 5 "verify" repaired "proved";call 6 "compare" repaired "proved";
    let response=exchange child 7 "tools/call" (`O ["name",`String "verify";
      "arguments",`O ["config",`String baseline;"api_group",`String "";"contract_version",`Number "5"]]) in
    check "MCP rejects group and schema substitution" (field "code" (field "error" response)=`Number "-32602");
    close_out child.input;
    let ready,_,_=Unix.select [child.output] [] [] 10. in
    check "MCP closes cleanly at EOF" (child.pending="" && ready<>[] && Unix.read child.output (Bytes.create 1) 0 1=0);
    let _,status=Unix.waitpid [] child.pid in child.reaped<-true;
    check "MCP resource session has no diagnostics" (status=Unix.WEXITED 0 && read child.error=""))
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
    "-c";"commit.gpgSign=false";"commit";"--quiet";"-m";"Approved collection-write contract"]);
  let approved=git ["rev-parse";"HEAD"] and event=Filename.concat directory "event.json" in
  write event (I.json (`O ["repository",`O ["full_name",`String "example/soundcheck"];
    "pull_request",`O ["base",`O ["sha",`String approved;"ref",`String "main";
      "repo",`O ["full_name",`String "example/soundcheck"]]]]));
  let weakened=contract ~version:5 () in write contract_path weakened;
  let code,stdout,stderr=run binary ["rbac";"verify";config_path;"--contract";contract_path;"--format";"json"] in
  check "candidate schema downgrade would hide the collection-write violation"
    (code=0 && stderr="" && string "result" (I.parse stdout)="proved");
  let execute mode candidate expected fragments =
    write config_path candidate;
    let settings=["GITHUB_WORKSPACE",workspace;"GITHUB_EVENT_PATH",event;"GITHUB_EVENT_NAME","pull_request";
      "GITHUB_REPOSITORY","example/soundcheck";"GITHUB_BASE_REF","main";"RUNNER_TEMP",runner_temp;
      "SOUNDCHECK_CONFIG_INPUT","snapshot.json";"SOUNDCHECK_CONTRACT_INPUT","contract.json";
      "SOUNDCHECK_CONNECTOR_INPUT","kubernetes-rbac";"SOUNDCHECK_MODE_INPUT",mode] in
    let inherited=Array.to_list (Unix.environment ()) |> List.filter (fun value ->
      not (List.exists (fun (key,_) -> String.starts_with ~prefix:(key^"=") value) settings)) in
    let env=Array.of_list (List.map (fun (key,value) -> key^"="^value) settings @ inherited) in
    let code,stdout,stderr=run ~env "bash" [script] in
    check ("approved v6 gate: "^stderr) (code=expected && stderr="");
    List.iter (fun part -> check ("gate output includes "^part) (contains stdout part))
      (["Approved contract: "^approved^":contract.json";profile;"\"schema_version\":6"] @ fragments);
    check "gate cleans frozen copies and leaves candidate contract alone"
      (Sys.readdir runner_temp=[||] && read contract_path=weakened) in
  execute "verify" baseline 3 ["pod-bulk-delete-forbidden";"deletecollection";"pods"];
  execute "repair" regression 3 ["Approved baseline: "^approved^":snapshot.json";"must_preserve";"nodes";"create"];
  execute "repair" repaired 0 ["rbac-repair-preservation proved"]
let () =
  if Array.length Sys.argv<>3 then failwith "expected CLI and approved-contract helper";
  let binary=Sys.argv.(1) and helper=Sys.argv.(2) in
  let directory=temporary_directory () in
  Fun.protect ~finally:(fun () -> cleanup directory) (fun () ->
    let contract_path=Filename.concat directory "contract.json" and baseline_path=Filename.concat directory "baseline.json" in
    write contract_path (contract ());write baseline_path baseline;
    let code,stdout,stderr=run binary ["profile";"kubernetes-rbac";"--contract-version";"6";"--format";"json"] in
    check "CLI selects collection-write profile" (code=0 && stderr="");
    let value=I.parse stdout in
    check "profile selects schema 6 without changing the profile envelope"
      (string "id" value=profile && field "schema_version" value=`Number "3"
       && field "contract_schema_version" value=`Number "6");
    check "profile publishes exactly the approved eight verbs"
      (List.sort compare (array "verbs" value)=List.sort compare
        (List.map (fun s -> `String s) ["get";"list";"watch";"update";"patch";"delete";"create";"deletecollection"]));
    let domains=array "resource_domains" value |> List.map (fun r ->
      string "api_group" r,string "resource" r,string "scope" r,string "resource_kind" r) |> List.sort compare in
    let expected=["","configmaps","namespaced","configmaps";"","secrets","namespaced","secrets";
      "","pods","namespaced","pods";"","services","namespaced","services";"","endpoints","namespaced","endpoints";
      "","nodes","cluster","nodes";"apps","deployments","namespaced","deployments.apps";
      "discovery.k8s.io","endpointslices","namespaced","endpointslices.discovery.k8s.io"] |> List.sort compare in
    check "resource catalogue remains the eight approved pairs" (domains=expected);
    let code,human,stderr=run binary ["profile";"kubernetes-rbac";"--contract-version";"6"] in
    check "human profile exposes new verbs and empty-name boundary"
      (code=0 && stderr="" && contains human profile && contains human "deletecollection" && contains human "empty");
    let code,stdout,stderr=run binary ["rbac";"check-contract";contract_path] in
    check "authoring review explains both collection operations without proving them"
      (code=0 && stderr="" && contains stdout "Contract schema: 6" && contains stdout "apps" &&
       contains stdout "create" && contains stdout "deletecollection" && contains stdout "empty" &&
       contains stdout "structure only");
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
    let missing=invoke ~evidence:true "missing-creation" denied "violated" in
    check "required grouped creation witness is explicit"
      (string "resource_kind" (field "object_request" (field "counterexample" missing))="deployments.apps"
       && string "action" (field "counterexample" missing)="create");
    let unsafe=invoke "forbidden-bulk-delete" baseline "violated" in
    check "bulk-deletion witness has no fabricated object name"
      (string "name" (field "object_request" (field "counterexample" unsafe))=""
       && string "action" (field "counterexample" unsafe)="deletecollection");
    let code,human,stderr=run binary ["rbac";"verify";baseline_path;"--contract";contract_path] in
    check "human violation identifies collection deletion"
      (code=3 && stderr="" && contains human "deletecollection" && contains human "pods");
    ignore (invoke ~before:baseline "valid" repaired "proved");
    let changed=invoke ~before:baseline ~evidence:true "operator-regression" regression "violated" in
    check "preservation includes unmentioned Node creation and identity"
      (string "resource_kind" (field "object_request" (field "counterexample" changed))="nodes"
       && string "principal" (field "counterexample" changed)="operator"
       && string "action" (field "counterexample" changed)="create"
       && string "namespace" (field "object_request" (field "counterexample" changed))="");
    let invalid=Filename.concat directory "invalid-contract.json" in
    let named_creation=match I.parse (contract ()) with
      | `O fields ->
        let clauses=match List.assoc "clauses" fields with
          | `A (`O required::rest) -> `A (`O (("names",strings ["worker"])::List.remove_assoc "names" required)::rest)
          | _ -> assert false in
        `O (("clauses",clauses)::List.remove_assoc "clauses" fields)
      | _ -> assert false in
    write invalid (I.json named_creation);
    let code,stdout,stderr=run binary ["rbac";"check-contract";invalid] in
    check "authoring rejects body-name restrictions instead of suggesting a proof"
      (code=2 && not (contains stdout "proved") && contains stderr "names");
    mcp_checks directory binary;
    gate_checks directory binary helper);
  Printf.printf "RBAC collection-write adapters: %d checks passed\n" !checks
