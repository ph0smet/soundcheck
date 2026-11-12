open Soundcheck_core
module K = Soundcheck_kubernetes_rbac
module I = K.Input

let checks = ref 0
let check label condition = incr checks; if not condition then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let field key = function
  | `O fields -> (match List.assoc_opt key fields with Some value -> value | None -> failwith ("missing " ^ key))
  | _ -> failwith ("not an object: " ^ key)
let string key value = I.str key (field key value)
let array key value = I.arr key (field key value)
let strings values = `A (List.map (fun value -> `String value) values)
let contains text fragment =
  let rec loop index = index + String.length fragment <= String.length text
    && (String.sub text index (String.length fragment) = fragment || loop (index + 1)) in loop 0
let read path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
      really_input_string channel (in_channel_length channel))
let write path value =
  let channel = open_out_bin path in
  Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () -> output_string channel value)
let rec cleanup path = match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR -> Array.iter (fun name -> cleanup (Filename.concat path name)) (Sys.readdir path);Unix.rmdir path
  | _ -> Unix.unlink path
let mkdir path = Unix.mkdir path 0o700
let temporary_directory () =
  let path = Filename.temp_file "soundcheck-rbac-read-adapters-" "" in
  Unix.unlink path;mkdir path;Unix.realpath path

let run ?env binary args =
  let output = Filename.temp_file "rbac-read-out-" "" and error = Filename.temp_file "rbac-read-err-" "" in
  Fun.protect ~finally:(fun () -> Sys.remove output;Sys.remove error) (fun () ->
      let out_fd = Unix.openfile output [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
      let err_fd = Unix.openfile error [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
      let argv = Array.of_list (binary::args) in
      let pid = match env with
        | None -> Unix.create_process binary argv Unix.stdin out_fd err_fd
        | Some env -> Unix.create_process_env binary argv env Unix.stdin out_fd err_fd in
      Unix.close out_fd;Unix.close err_fd;
      let _,status = Unix.waitpid [] pid in
      let code = match status with Unix.WEXITED value -> value | _ -> failwith "child terminated" in
      code,read output,read error)

(* Synthetic inputs are local to this adapter test. The connector/conformance
   suites own their public corpus and independently test target semantics. *)
let scope ?(version=2) ?(subject="reader") ?(namespace=Some "payments")
    ?(resource="secrets") ?(names=None) verb =
  ["subject",`String subject;
   "namespace",(match namespace with None -> `Null | Some value -> `String value);
   "resource",`String resource;
   "names",(match names with None -> `Null | Some values -> strings values)]
  @ if version=1 then [] else ["verb",`String verb]
let clause name kind scope = `O (["name",`String name;"kind",`String kind] @ scope)
let context = `O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
  "identities",`A (List.map (fun name -> `O ["username",`String name;
    "groups",strings ["system:authenticated"]]) ["reader";"operator"])]
let contract ?(version=2) ?(all_namespaces=false) () =
  let config verb = scope ~version ~namespace:(Some "frontend") ~resource:"configmaps"
      ~names:(if verb="get" then Some ["settings"] else None) verb in
  let forbidden = if all_namespaces then
      [clause "secret-list-all-namespaces" "must_not_grant"
         (scope ~namespace:None ~names:(Some ["signing-key"]) "list")]
    else List.map (fun verb -> clause ("secret-" ^ verb) "must_not_grant" (scope ~version verb))
        (if version=1 then ["get"] else ["get";"list";"watch"]) in
  let required = clause "config-get" "must_allow" (config "get") ::
    (if version=1 || all_namespaces then [] else [clause "config-watch" "must_allow" (config "watch")]) in
  I.json (`O ["schema_version",`Number (string_of_int version);"kind",`String "kubernetes-rbac-access";
    "context",context;"clauses",`A (required @ forbidden);
    "change_scope",`A (List.map (fun verb -> `O (scope ~version verb))
      (if version=1 then ["get"] else ["get";"list";"watch"]))])

let rule ?names resource verbs = `O (["apiGroups",strings [""];"resources",strings [resource];
  "verbs",strings verbs] @ match names with None -> [] | Some names -> ["resourceNames",strings names])
let role namespace name rules = `O ["apiVersion",`String "rbac.authorization.k8s.io/v1";
  "kind",`String "Role";"metadata",`O ["name",`String name;"namespace",`String namespace];
  "rules",`A rules]
let binding namespace name subject = `O ["apiVersion",`String "rbac.authorization.k8s.io/v1";
  "kind",`String "RoleBinding";"metadata",`O ["name",`String name;"namespace",`String namespace];
  "subjects",`A [`O ["kind",`String "User";"name",`String subject;"apiGroup",`String "rbac.authorization.k8s.io"]];
  "roleRef",`O ["kind",`String "Role";"name",`String name;"apiGroup",`String "rbac.authorization.k8s.io"]]
let snapshot ?(config_verbs=["get";"list";"watch"]) ?(secret_verbs=[]) ?secret_names
    ?(operator=true) ?(global=false) () =
  let config = [role "frontend" "configuration" [rule "configmaps" config_verbs];
    binding "frontend" "configuration" "reader"] in
  let secrets = if secret_verbs=[] then [] else
      [role "payments" "secrets" [rule ?names:secret_names "secrets" secret_verbs];
       binding "payments" "secrets" "reader"] in
  let operators = if operator then [role "ops" "observability" [rule "configmaps" ["watch"]];
      binding "ops" "observability" "operator"] else [] in
  let global = if global then [
    `O ["apiVersion",`String "rbac.authorization.k8s.io/v1";"kind",`String "ClusterRole";
        "metadata",`O ["name",`String "global-secrets"];
        "rules",`A [rule ~names:["signing-key"] "secrets" ["list"]]];
    `O ["apiVersion",`String "rbac.authorization.k8s.io/v1";"kind",`String "ClusterRoleBinding";
        "metadata",`O ["name",`String "global-secrets"];
        "subjects",`A [`O ["kind",`String "User";"name",`String "reader";"apiGroup",`String "rbac.authorization.k8s.io"]];
        "roleRef",`O ["kind",`String "ClusterRole";"name",`String "global-secrets";"apiGroup",`String "rbac.authorization.k8s.io"]]] else [] in
  I.json (`O ["apiVersion",`String "v1";"kind",`String "List";"items",`A (config @ secrets @ operators @ global)])

let profile_v1 = "kubernetes-rbac-v1.34-get-v3"
let profile_v2 = "kubernetes-rbac-v1.34-read-v3"

let with_urls ?(urls=["*"]) ?(mixed=false) source =
  let fields = match I.parse source with `O fields -> fields | _ -> assert false in
  let items = I.arr "items" (List.assoc "items" fields) in
  let url_rule = `O (["verbs",strings ["get"];"nonResourceURLs",strings urls]
    @ if mixed then ["resources",strings ["secrets"]] else []) in
  let additional = [
    `O ["apiVersion",`String "rbac.authorization.k8s.io/v1";"kind",`String "ClusterRole";
      "metadata",`O ["name",`String "discovery"];"rules",`A [url_rule]];
    `O ["apiVersion",`String "rbac.authorization.k8s.io/v1";"kind",`String "ClusterRoleBinding";
      "metadata",`O ["name",`String "discovery"];
      "subjects",`A [`O ["kind",`String "User";"name",`String "reader";"apiGroup",`String "rbac.authorization.k8s.io"]];
      "roleRef",`O ["kind",`String "ClusterRole";"name",`String "discovery";"apiGroup",`String "rbac.authorization.k8s.io"]]] in
  I.json (`O (List.map (fun (key,value) -> key,if key="items" then `A (items@additional) else value) fields))

let assert_report ~version ~spec outcome report =
  check "report schema remains 10" (field "schema_version" report=`Number "10");
  check "expected verdict" (string "result" report=outcome);
  let frozen = field "frozen_spec" report in
  check "exact frozen version and canonical contract"
    (field "schema_version" frozen=`Number (string_of_int version)
     && string "canonical" frozen=K.Contract_spec.canonical spec);
  check "profile selected by frozen contract version"
    (string "profile" (field "assurance" report)=(if version=1 then profile_v1 else profile_v2))

let witness_request witness : Ir.request =
  let object_ = field "object_request" witness in
  {principal=Authenticated (string "principal" witness);action=string "action" witness;
   resource="";context=[];source=0l;host="";scheme="";sni="";
   object_request=Some {namespace=string "namespace" object_;resource_kind=string "resource_kind" object_;name=string "name" object_}}
let assert_witness spec ?before ~after report =
  if string "result" report="violated" then begin
    let witness = field "counterexample" report in
    let request = witness_request witness in
    let coordinates = Option.get request.object_request in
    check "typed read action" (List.mem request.action ["get";"list";"watch"]);
    check "typed namespace preserves all-namespace empty coordinate"
      (coordinates.namespace="" || I.dns_label coordinates.namespace);
    check "typed name preserves unfiltered empty coordinate"
      (coordinates.name="" || I.dns_subdomain coordinates.name);
    check "get retains named-object semantics"
      (request.action<>"get" || (coordinates.namespace<>"" && coordinates.name<>""));
    let username = string "principal" witness in
    let identity = List.find (fun (value : K.Identity.identity) -> value.username=username) (K.Contract_spec.identities spec) in
    check "witness groups remain frozen" (field "identity_groups" witness=strings identity.groups);
    let policy source = K.Lower.policy spec (ok (K.Snapshot.of_string source)) in
    let candidate = policy after in
    let clause = field "clause" report in
    let valid = if string "kind" clause="must_preserve" then
        Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes spec))
          (policy (Option.get before)) candidate request
      else Witness.clause candidate
          (List.find (fun value -> Contract.name value=string "name" clause) (K.Contract_spec.to_contract spec).clauses) request in
    check "reported read witness satisfies the actual obligation" valid;
    check "grant IDs describe the candidate decision"
      (field "granting_rules" witness=strings (K.Lower.granting_rules candidate request))
  end

let assert_coordinate report ~action ~namespace ~name =
  let witness = field "counterexample" report in
  let object_ = field "object_request" witness in
  check "exact read action" (string "action" witness=action);
  check "exact namespace coordinate" (string "namespace" object_=namespace);
  Option.iter (fun name -> check "exact effective name coordinate" (string "name" object_=name)) name

let saved_model value : Solve.model =
  let object_ = field "object_request" value in
  {path=string "path" value;method_=string "method" value;is_anon=false;
   principal_name=Some (string "principal_name" value);
   object_request=Some {namespace=string "namespace" object_;resource_kind=string "resource_kind" object_;name=string "name" object_};
   src_ip=(ok (Cidr.parse (string "source_ip" value))).base;host=string "host" value;
   scheme=string "scheme" value;sni=string "sni" value;
   headers=List.map (fun item -> string "name" item,string "value" item) (array "headers" value)}
let assert_evidence directory spec ?before ~after stdout =
  let artifact metadata =
    let value = read (Filename.concat directory (string "path" metadata)) in
    check "evidence artifact checksum" (string "sha256" metadata=Sha256.string value);value in
  let manifest = I.parse (read (Filename.concat directory "manifest.json")) in
  check "evidence format does not change for the new profile"
    (field "schema_version" manifest=`Number (if before=None then "2" else "3"));
  let input role source metadata =
    check (role ^ " input digest") (string "sha256" metadata=Sha256.string source);
    check (role ^ " input byte length") (field "size_bytes" metadata=`Number (string_of_int (String.length source))) in
  (match before with
   | None -> input "config" after (field "config" manifest)
   | Some before ->
     check "comparison operation stays explicit" (string "operation" manifest="repair_comparison");
     input "before" before (field "before" (field "inputs" manifest));
     input "after" after (field "after" (field "inputs" manifest));
     let candidate = I.parse (artifact (field "candidate_report" manifest)) in
     assert_report ~version:2 ~spec "proved" candidate);
  check "evidence report is exactly the same invocation's stdout" (artifact (field "report" manifest)=stdout);
  check "canonical v2 contract is retained" (artifact (field "contract" manifest)=K.Contract_spec.canonical spec ^ "\n");
  let profile = field "assurance_profile" manifest in
  check "evidence references the read profile" (string "id" profile=profile_v2);
  check "evidence includes the full selected profile"
    (artifact (field "artifact" profile)=K.Assurance.profile_json ~version:2 () ^ "\n");
  check "supported v2 plan is complete" (string "status" (field "obligation_plan" manifest)="complete");
  let policy source = K.Lower.policy spec (ok (K.Snapshot.of_string source)) in
  let after_policy = policy after in
  let clauses = K.Contract_spec.to_contract spec in
  let plan = Contract_verify.plan after_policy clauses in
  let entries = array "obligations" manifest in
  check "all candidate and preservation queries retained" (List.length entries=List.length plan + if before=None then 0 else 1);
  List.iter (fun entry ->
    let id = string "id" entry in
    let preservation = id="preservation-outside-change-scope" in
    let obligation = if preservation then None else Some (List.find (fun (value : Contract_verify.obligation) -> value.id=id) plan) in
    let expected_query = match obligation with Some value -> value.smtlib | None ->
        Smt_encode.decision_equivalence_query ~when_:(Ir.Not (K.Contract_spec.approved_changes spec)) (policy (Option.get before)) after_policy in
    check "saved query includes the actual read domain and obligation" (artifact (field "query" entry)=expected_query);
    if field "solver_result" entry=`String "sat" then begin
      let request = Witness.request_of_model (saved_model (field "model" entry)) in
      let valid = match obligation with
        | None -> Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes spec)) (policy (Option.get before)) after_policy request
        | Some value ->
          let related = List.map (fun name -> List.find (fun clause -> Contract.name clause=name) clauses.clauses) value.clauses in
          if value.phase=Contract_verify.Clause then Witness.clause after_policy (List.hd related) request
          else Witness.condition ~domain:after_policy.request_domain (Ir.And (List.map Contract.request_class related)) request in
      check "saved read model is valid for its exact obligation" valid
    end) entries;
  let report = I.parse stdout in
  if string "result" report="violated" then begin
    let decisive = List.find (fun entry -> field "solver_result" entry=`String "sat") (List.rev entries) in
    let model = field "model" decisive and witness = field "counterexample" report in
    check "report and evidence agree on the read verb" (field "action" witness=field "method" model);
    check "report and evidence agree on exact typed collection coordinates"
      (field "object_request" witness=field "object_request" model && field "principal" witness=field "principal_name" model)
  end

let annotation_checks () =
  let render action namespace name =
    let witness : Report.counterexample = {principal="reader";action;path="";route=None;service=None;
      shadowed_route=None;shadowed_service=None;host="";scheme="";sni="";source_ip=0l;headers=[];
      object_request=Some {namespace;resource_kind="secrets";name};identity_groups=Some [];
      granting_rules=[];note="RBAC decision: Allow"} in
    Soundcheck_ci.Github_annotation.render ~file:"rbac.json"
      {Report.result=Violated witness;property_name="rbac-access";property_description="";
       assurance=None;frozen_spec=None;clause=None} in
  let ordinary = render "get" "payments" "signing-key" in
  check "named-get annotation remains byte compatible"
    (ordinary="::error file=rbac.json,title=Soundcheck%3A rbac-access::rbac-access violated; reader get secrets/signing-key in namespace payments; identity groups []; granting rules []; RBAC decision: Allow");
  let global = render "list" "" "" in
  check "empty authorization namespace does not assume resource scope"
    (contains global "reader list secrets with empty authorization namespace with no exact-name restriction");
  let selected = render "watch" "payments" "signing-key" in
  check "watch name is an effective name without invented selector provenance"
    (contains selected "reader watch secrets in namespace payments with effective name signing-key");
  let injected = render "watch" "payments\n::notice::bad" "key%\r\n::notice::bad" in
  check "new annotation wording retains centralized workflow escaping"
    (not (contains injected "\n") && contains injected "%0A::notice::bad" && contains injected "key%25%0D%0A")

let cli_checks directory binary =
  let contract_path = Filename.concat directory "contract.json" in
  let contract_source = contract () and old_contract = contract ~version:1 () in
  let spec = ok (K.Contract_spec.of_string contract_source) in
  let old_spec = ok (K.Contract_spec.of_string old_contract) in
  check "contract API exposes the frozen version" (K.Contract_spec.version spec=2 && K.Contract_spec.version old_spec=1);
  write contract_path contract_source;
  List.iter (fun (args,expected) ->
    let code,stdout,stderr = run binary (["profile";"kubernetes-rbac"] @ args @ ["--format";"json"]) in
    check "version-selected profile command" (code=0 && stderr="" && string "id" (I.parse stdout)=expected))
    [[],profile_v1;["--contract-version";"2"],profile_v2];
  let invalid_code,invalid_stdout,_ = run binary ["profile";"kubernetes-rbac";"--contract-version";"8";"--format";"json"] in
  check "unsupported profile versions cannot silently select a model" (invalid_code=2 && invalid_stdout="");
  let baseline = snapshot ~secret_verbs:["get";"list";"watch"] () in
  let repaired = snapshot () in
  let baseline_path = Filename.concat directory "baseline.json" in
  write baseline_path baseline;
  let invoke ?(contract_file=contract_path) ?evidence ?before name source outcome =
    let source_path = Filename.concat directory (name ^ ".json") in write source_path source;
    let args = match before with None -> ["verify";source_path] | Some path -> ["compare";path;source_path] in
    let code,stdout,stderr = run binary ("rbac"::args @ ["--contract";contract_file;"--format";"json"]
      @ match evidence with None -> [] | Some path -> ["--evidence-dir";path]) in
    check ("CLI verdict: " ^ name ^ ": " ^ stderr)
      (code=(if outcome="proved" then 0 else if outcome="unknown" then 4 else 3) && stderr="");
    let report = I.parse stdout in
    let version,spec = if contract_file=contract_path then 2,spec else 1,old_spec in
    assert_report ~version ~spec outcome report;
    assert_witness spec ?before:(Option.map read before) ~after:source report;
    Option.iter (fun path -> assert_evidence path spec ?before:(Option.map read before) ~after:source stdout) evidence;
    report in
  let old_path = Filename.concat directory "v1-contract.json" in write old_path old_contract;
  let unsupported = invoke "unsupported-read-snapshot" (repaired ^ "{}") "unknown" in
  check "unsupported v2 input does not fall back to an older model"
    (string "status" (field "assurance" unsupported)="unsupported");
  let leftover_list = snapshot ~secret_verbs:["list"] () in
  ignore (invoke ~contract_file:old_path "v1-leftover-list" leftover_list "proved");
  let list = invoke "leftover-list" leftover_list "violated" in
  assert_coordinate list ~action:"list" ~namespace:"payments" ~name:None;
  let watch = invoke "leftover-watch" (snapshot ~secret_verbs:["watch"] ()) "violated" in
  assert_coordinate watch ~action:"watch" ~namespace:"payments" ~name:None;
  let selected = invoke ~evidence:(Filename.concat directory "selected-evidence") "selected-list"
      (snapshot ~secret_verbs:["list"] ~secret_names:["signing-key"] ()) "violated" in
  assert_coordinate selected ~action:"list" ~namespace:"payments" ~name:(Some "signing-key");
  let missing_watch = invoke "missing-required-watch" (snapshot ~config_verbs:["get";"list"] ()) "violated" in
  assert_coordinate missing_watch ~action:"watch" ~namespace:"frontend" ~name:None;
  check "watch functionality is a must-allow failure" (string "kind" (field "clause" missing_watch)="must_allow");
  ignore (invoke ~before:baseline_path "valid-repair" repaired "proved");
  let url_source = with_urls repaired and url_changed = with_urls ~urls:["/version"] repaired in
  let url_before = Filename.concat directory "url-before.json" in write url_before url_source;
  ignore (invoke "url-coexistence" url_source "proved");
  ignore (invoke ~before:url_before ~evidence:(Filename.concat directory "url-edit-evidence")
    "url-only-edit" url_changed "proved");
  check "URL edit is still a distinct evidence input" (Sha256.string url_source<>Sha256.string url_changed);
  ignore (invoke "invalid-mixed-url-rule" (with_urls ~mixed:true repaired) "unknown");
  let config_regression = invoke ~before:baseline_path "config-list-regression" (snapshot ~config_verbs:["get";"watch"] ()) "violated" in
  assert_coordinate config_regression ~action:"list" ~namespace:"frontend" ~name:None;
  check "unmentioned ConfigMap list grant must be preserved" (string "kind" (field "clause" config_regression)="must_preserve");
  let operator_regression = snapshot ~operator:false () in
  let operator = invoke ~before:baseline_path ~evidence:(Filename.concat directory "preservation-evidence")
      "operator-watch-regression" operator_regression "violated" in
  assert_coordinate operator ~action:"watch" ~namespace:"ops" ~name:None;
  check "unrelated operator identity remains in preservation domain"
    (string "principal" (field "counterexample" operator)="operator" && string "kind" (field "clause" operator)="must_preserve");
  let global_contract = contract ~all_namespaces:true () in
  let global_spec = ok (K.Contract_spec.of_string global_contract) in
  let global_contract_path = Filename.concat directory "all-namespaces-contract.json" in write global_contract_path global_contract;
  let global_source = snapshot ~global:true () in
  let global_path = Filename.concat directory "global.json" in write global_path global_source;
  let global_evidence = Filename.concat directory "global-evidence" in
  let code,stdout,stderr = run binary ["rbac";"verify";global_path;"--contract";global_contract_path;
      "--format";"json";"--evidence-dir";global_evidence] in
  check "all-namespace CLI violation" (code=3 && stderr="");
  let global = I.parse stdout in assert_report ~version:2 ~spec:global_spec "violated" global;
  assert_witness global_spec ~after:global_source global;
  assert_coordinate global ~action:"list" ~namespace:"" ~name:(Some "signing-key");
  assert_evidence global_evidence global_spec ~after:global_source stdout;
  spec,contract_source,old_contract,baseline,repaired,operator_regression

type child = {pid:int;input:out_channel;output:Unix.file_descr;error_path:string;
  mutable pending:string;mutable reaped:bool}
let with_child directory binary args action =
  let input_read,input_write = Unix.pipe ~cloexec:true () and output_read,output_write = Unix.pipe ~cloexec:true () in
  let error_path = Filename.concat directory "mcp.stderr" in
  let error = Unix.openfile error_path [Unix.O_WRONLY;Unix.O_CREAT;Unix.O_TRUNC] 0o600 in
  let pid = Unix.create_process binary (Array.of_list (binary::args)) input_read output_write error in
  List.iter Unix.close [input_read;output_write;error];
  let child = {pid;input=Unix.out_channel_of_descr input_write;output=output_read;error_path;pending="";reaped=false} in
  Fun.protect ~finally:(fun () -> close_out_noerr child.input;
    if not child.reaped then begin (try Unix.kill child.pid Sys.sigkill with Unix.Unix_error (Unix.ESRCH,_,_) -> ());ignore (Unix.waitpid [] child.pid) end;
    Unix.close child.output) (fun () -> action child)
let send child value = output_string child.input (I.json value);output_char child.input '\n';flush child.input
let receive child =
  let deadline = Unix.gettimeofday () +. 45. in
  let rec loop () = match String.index_opt child.pending '\n' with
    | Some index ->
      let line = String.sub child.pending 0 index in
      child.pending <- String.sub child.pending (index+1) (String.length child.pending-index-1);I.parse line
    | None ->
      let timeout = deadline -. Unix.gettimeofday () in
      if timeout<=0. || (let ready,_,_ = Unix.select [child.output] [] [] timeout in ready=[]) then failwith "MCP response timed out";
      let bytes = Bytes.create 4096 in let count = Unix.read child.output bytes 0 (Bytes.length bytes) in
      if count=0 then failwith ("MCP unexpectedly exited: " ^ read child.error_path);
      child.pending <- child.pending ^ Bytes.sub_string bytes 0 count;loop () in loop ()
let rpc id method_ params = `O ["jsonrpc",`String "2.0";"id",`Number (string_of_int id);
  "method",`String method_;"params",params]
let exchange child id method_ params =
  send child (rpc id method_ params);
  let response = receive child in
  check "MCP envelope and ID preserved" (field "jsonrpc" response=`String "2.0" && field "id" response=`Number (string_of_int id));response
let mcp_checks directory binary spec contract_source old_contract baseline repaired regression =
  let contract_path = Filename.concat directory "mcp-contract.json" and baseline_path = Filename.concat directory "mcp-baseline.json" in
  write contract_path contract_source;write baseline_path baseline;
  with_child directory binary ["mcp";"--connector";"kubernetes-rbac";"--contract";contract_path;"--baseline";baseline_path] (fun child ->
    ignore (field "result" (exchange child 1 "initialize" (`O ["protocolVersion",`String "2024-11-05";
      "capabilities",`O [];"clientInfo",`O ["name",`String "read-acceptance";"version",`String "1"]])));
    send child (`O ["jsonrpc",`String "2.0";"method",`String "notifications/initialized"]);
    let discovery = field "result" (exchange child 2 "tools/list" (`O [])) in
    let tools = array "tools" discovery in
    check "v2 MCP retains config-only tools" (List.map (string "name") tools=["verify";"compare"]);
    List.iter (fun tool -> check "v2 request verbs cannot be substituted through tool arguments"
      (field "required" (field "inputSchema" tool)=strings ["config"]
       && field "additionalProperties" (field "inputSchema" tool)=`Bool false)) tools;
    check "MCP discovery binds initial baseline" (contains (string "description" (List.nth tools 1)) (Sha256.string baseline));
    (* This barrier confirms startup loading finished. Neither replacement nor
       deletion can alter the captured v2 contract or preservation baseline. *)
    write contract_path old_contract;write baseline_path regression;
    let call id name source outcome =
      let result = field "result" (exchange child id "tools/call" (`O ["name",`String name;
        "arguments",`O ["config",`String source]])) in
      let report = field "structuredContent" result in
      let text = string "text" (List.hd (array "content" result)) in
      check "MCP text and typed read report agree" (I.parse text=report);
      assert_report ~version:2 ~spec outcome report;
      assert_witness spec ?before:(if name="compare" then Some baseline else None) ~after:source report;report in
    let leftover = call 3 "verify" (snapshot ~secret_verbs:["watch"] ()) "violated" in
    assert_coordinate leftover ~action:"watch" ~namespace:"payments" ~name:None;
    let changed = call 4 "compare" regression "violated" in
    assert_coordinate changed ~action:"watch" ~namespace:"ops" ~name:None;
    Sys.remove contract_path;Sys.remove baseline_path;
    ignore (call 5 "verify" repaired "proved");
    ignore (call 6 "compare" repaired "proved");
    let rejected = exchange child 7 "tools/call" (`O ["name",`String "verify";
      "arguments",`O ["config",`String repaired;"contract_version",`Number "1";"verb",`String "get"]]) in
    check "MCP cannot downgrade the frozen read requirement" (field "code" (field "error" rejected)=`Number "-32602");
    ignore (call 8 "verify" (with_urls repaired) "proved");
    ignore (call 9 "compare" (with_urls ~urls:["/version"] repaired) "proved");
    ignore (call 10 "verify" (with_urls ~mixed:true repaired) "unknown");
    close_out child.input;
    check "MCP emits no unsolicited responses" (child.pending="");
    let ready,_,_ = Unix.select [child.output] [] [] 10. in
    check "MCP closes stdout at EOF" (ready<>[] && Unix.read child.output (Bytes.create 1) 0 1=0);
    let _,status = Unix.waitpid [] child.pid in child.reaped <- true;
    check "MCP read session exits cleanly" (status=Unix.WEXITED 0 && read child.error_path=""))

let gate_checks directory binary helper contract_source old_contract baseline repaired regression =
  let workspace = Filename.concat directory "workspace" and action = Filename.concat directory "trusted-action"
  and runner_temp = Filename.concat directory "runner-temp" in
  List.iter mkdir [workspace;action;runner_temp];
  List.iter (fun path -> mkdir (Filename.concat action path)) ["scripts";"_build"];
  mkdir (Filename.concat action "_build/default");mkdir (Filename.concat action "_build/default/cli");
  let script = Filename.concat action "scripts/verify-approved-contract.sh" in write script (read helper);
  Unix.symlink (Unix.realpath binary) (Filename.concat action "_build/default/cli/main.exe");
  let git args =
    let code,stdout,stderr = run "git" (["-c";"core.hooksPath=/dev/null";"-C";workspace] @ args) in
    check ("local gate git: " ^ String.concat " " args ^ stderr) (code=0);String.trim stdout in
  ignore (git ["init";"--quiet"]);
  let config_path = Filename.concat workspace "snapshot.json" and contract_path = Filename.concat workspace "contract.json" in
  write config_path baseline;write contract_path contract_source;
  ignore (git ["add";"--";"snapshot.json";"contract.json"]);
  ignore (git ["-c";"user.name=Soundcheck acceptance";"-c";"user.email=acceptance@example.invalid";
    "-c";"commit.gpgSign=false";"commit";"--quiet";"-m";"Approved v2 read requirements and baseline"]);
  let approved_sha = git ["rev-parse";"HEAD"] in
  let event = Filename.concat directory "event.json" in
  write event (I.json (`O ["repository",`O ["full_name",`String "example/soundcheck"];
    "pull_request",`O ["base",`O ["sha",`String approved_sha;"ref",`String "main";
      "repo",`O ["full_name",`String "example/soundcheck"]]] ]));
  write contract_path old_contract;
  let base_env = Array.to_list (Unix.environment ()) in
  let execute mode source expected fragments =
    write config_path source;
    let settings = ["GITHUB_WORKSPACE",workspace;"GITHUB_EVENT_PATH",event;"GITHUB_EVENT_NAME","pull_request";
      "GITHUB_REPOSITORY","example/soundcheck";"GITHUB_BASE_REF","main";"RUNNER_TEMP",runner_temp;
      "SOUNDCHECK_CONFIG_INPUT","snapshot.json";"SOUNDCHECK_CONTRACT_INPUT","contract.json";
      "SOUNDCHECK_CONNECTOR_INPUT","kubernetes-rbac";"SOUNDCHECK_MODE_INPUT",mode] in
    let inherited = List.filter (fun entry -> not (List.exists (fun (key,_) -> String.starts_with ~prefix:(key ^ "=") entry) settings)) base_env in
    let env = Array.of_list (List.map (fun (key,value) -> key ^ "=" ^ value) settings @ inherited) in
    let code,stdout,stderr = run ~env "bash" [script] in
    check ("approved v2 Action " ^ mode ^ ": " ^ stderr) (code=expected && stderr="");
    check "Action used immutable approved contract commit" (contains stdout ("Approved contract: " ^ approved_sha ^ ":contract.json"));
    check "Action report retains v2 profile" (contains stdout profile_v2);
    List.iter (fun fragment -> check ("Action output contains " ^ fragment) (contains stdout fragment)) fragments;
    check "Action removes approved temporary inputs" (Sys.readdir runner_temp=[||]);
    check "Action never rewrites candidate contract" (read contract_path=old_contract) in
  execute "verify" (snapshot ~secret_verbs:["list"] ()) 3 ["must_not_grant";"reader list secrets";"\"schema_version\":2"];
  execute "repair" regression 3 ["Approved baseline: " ^ approved_sha ^ ":snapshot.json";"must_preserve";"operator watch configmaps"];
  execute "repair" repaired 0 ["rbac-repair-preservation proved"];
  execute "repair" (with_urls repaired) 0 ["rbac-repair-preservation proved"];
  execute "verify" (with_urls ~mixed:true repaired) 4 ["unknown";"unsupported"]

let () =
  if Array.length Sys.argv<>3 then failwith "expected CLI binary and approved-contract helper";
  let binary = Sys.argv.(1) and helper = Sys.argv.(2) in
  let directory = temporary_directory () in
  Fun.protect ~finally:(fun () -> cleanup directory) (fun () ->
    annotation_checks ();
    let spec,source,old,baseline,repaired,regression = cli_checks directory binary in
    mcp_checks directory binary spec source old baseline repaired regression;
    gate_checks directory binary helper source old baseline repaired regression);
  Printf.printf "RBAC read adapters: %d checks passed\n" !checks
