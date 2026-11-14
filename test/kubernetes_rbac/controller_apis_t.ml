open Soundcheck_core
module K = Soundcheck_kubernetes_rbac
module I = K.Input

let checks = ref 0
let check label value = incr checks; if not value then failwith label
let ok = function Ok value -> value | Error message -> failwith message
let read path = let input = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in input)
    (fun () -> really_input_string input (in_channel_length input))
let strings values = `A (List.map (fun value -> `String value) values)
let field key = function `O fields -> List.assoc key fields | _ -> failwith key
let array key value = I.arr key (field key value)
let set key value fields = (key,value) :: List.remove_assoc key fields
let replace key value = function `O fields -> `O (set key value fields) | _ -> assert false
let scope ?(subject="controller") ?(group="") ?(resource="configmaps")
    ?(subresource="") ?(operation="get") ?(namespace=`String "team-a")
    ?(names=strings ["settings"]) () =
  ["request_kind",`String "resource";"subject",`String subject;
   "operation",`String operation;"api_group",`String group;
   "resource",`String resource;"subresource",`String subresource;
   "namespace",namespace;"names",names]
let contract ?(version=10) ?(allow=scope ())
    ?(deny=scope ~resource:"secrets" ~names:`Null ()) ?(changes=[]) () =
  `O ["schema_version",`Number (string_of_int version);"kind",`String "kubernetes-rbac-access";
    "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
      "identities",`A [`O ["username",`String "controller";"groups",strings ["controller-team"]];
                       `O ["username",`String "reviewer";"groups",strings []]]];
    "custom_resources",`A [];
    "clauses",`A [`O (["name",`String "required";"kind",`String "must_allow"]@allow);
                  `O (["name",`String "forbidden";"kind",`String "must_not_grant"]@deny)];
    "change_scope",`A (List.map (fun value -> `O value) changes)]
let parse value = K.Contract_spec.of_string (I.json value)
let spec value = ok (parse value)
let rule ?(verbs=["*"]) ?(groups=["*"]) ?(names=[]) resources =
  `O ["apiGroups",strings groups;"resources",strings resources;
      "verbs",strings verbs;"resourceNames",strings names]
let grant ?(subject="controller") ?(subject_kind="User") ?(binding_kind="ClusterRoleBinding")
    ?(namespace="team-a") name rules =
  let api = "rbac.authorization.k8s.io" in
  [`O ["apiVersion",`String (api^"/v1");"kind",`String "ClusterRole";
       "metadata",`O ["name",`String name];"rules",`A rules];
   `O ["apiVersion",`String (api^"/v1");"kind",`String binding_kind;
       "metadata",`O (["name",`String name] @ if binding_kind="RoleBinding" then ["namespace",`String namespace] else []);
       "roleRef",`O ["apiGroup",`String api;"kind",`String "ClusterRole";"name",`String name];
       "subjects",`A [`O ["kind",`String subject_kind;"apiGroup",`String api;"name",`String subject]]]]
let snapshot items = I.json (`O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items])
let policy s source = K.Lower.policy s (ok (K.Snapshot.of_string source))
let kind group resource subresource = resource ^ (if subresource="" then "" else "/"^subresource) ^ "."^group
let request ?(subject="controller") group resource subresource operation namespace name : Ir.request =
  {principal=Authenticated subject;action=operation;resource="";context=[];source=0l;
   host="";scheme="";sni="";object_request=Some {namespace;resource_kind=kind group resource subresource;name}}
let evaluation group resource subresource operation namespace name =
  I.json (`A [`O ["id",`String "request";"username",`String "controller";
    "groups",strings ["controller-team"];"operation",`String operation;
    "apiGroup",`String group;"resource",`String resource;"subresource",`String subresource;
    "namespace",`String namespace;"name",`String name;"resourceRequest",`Bool true]])

(* Source-derived endpoint expectations, deliberately independent of the
   production catalogue. See controller-apis/source-pins.json and the native
   APIInstaller/RequestInfo conformance suite. *)
let initial = ["get";"list";"watch";"create";"update";"patch";"delete";"deletecollection"]
let entries = [
  "admissionregistration.k8s.io","validatingwebhookconfigurations","",initial;
  "admissionregistration.k8s.io","mutatingwebhookconfigurations","",initial;
  "apiextensions.k8s.io","customresourcedefinitions","",initial;
  "apiextensions.k8s.io","customresourcedefinitions","status",["get";"update";"patch"];
  "authorization.k8s.io","subjectaccessreviews","",["create"];
  "authentication.k8s.io","tokenreviews","",["create"]]

let legacy legacy_path =
  (* Captured from ec131ce before schema-10 changes; existing coverage_t also
     freezes schema 1–8 canonical contracts and profiles. *)
  check "schema9 profile unchanged"
    (Sha256.string (K.Assurance.profile_json ~version:9 ()) =
     "077b3f9ef47a670a5edd3bbff7eacea929f21eff12f477674dfacc9a1f581dff");
  let old = ok (K.Contract_spec.of_string (read legacy_path)) in
  check "schema9 frozen contract unchanged"
    (Sha256.string (K.Contract_spec.canonical old) =
     "537788f3542d703740f0e146380477c149b4fc9423ba6a0e3ddf056cf0addd3a");
  let old_domain = K.Lower.domain (spec (contract ~version:9 ())) in
  List.iter (fun (group,resource,subresource,operations) ->
    List.iter (fun operation ->
      let name = if List.mem operation ["create";"deletecollection"] then "" else "object.example" in
      check "schema9 excludes new authorization classes"
        (not (Ir.matches old_domain (request group resource subresource operation "" name)));
      check "schema9 rejects new clauses"
        (Result.is_error (parse (contract ~version:9
          ~allow:(scope ~group ~resource ~subresource ~operation ~namespace:`Null
            ~names:(if name="" then `Null else strings [name]) ()) ())))) operations) entries;
  let profile = I.parse (K.Assurance.profile_json ~version:10 ()) in
  check "controller profile identity" (field "id" profile=`String "kubernetes-rbac-v1.34-controller-apis-v1");
  check "profile wire schema remains6" (field "schema_version" profile=`Number "6");
  check "contract schema10 is explicit" (field "contract_schema_version" profile=`Number "10");
  let domains = array "resource_domains" profile in
  check "37 fixed entries" (List.length domains=37);
  check "252 fixed operations" (List.fold_left (fun n row -> n+List.length (array "operations" row)) 0 domains=252);
  let updated = spec (contract ()) in
  List.iter (fun entry ->
    let old_ops = K.Resource_domain.operations ~version:9 entry in
    check "existing operations do not grow" (old_ops=K.Resource_domain.operations ~version:10 entry);
    List.iter (fun operation -> List.iter (fun namespace -> List.iter (fun name ->
      let r : Ir.request = { (request "unused" "unused" "" operation namespace name) with
        object_request=Some {namespace;name;resource_kind=K.Resource_domain.kind entry} } in
      check "old request membership preserved" (Ir.matches old_domain r=Ir.matches (K.Lower.domain updated) r))
      ["";"object";"other.example"]) ["";"team-a";"object"]) old_ops)
    (K.Resource_domain.for_version 9)

let domains () =
  let s = spec (contract ()) in
  let all = policy s (snapshot (grant "all" [rule ["*"]])) in
  let local = policy s (snapshot (grant ~binding_kind:"RoleBinding" "local" [rule ["*"]])) in
  List.iter (fun (group,resource,subresource,allowed) ->
    List.iter (fun operation -> List.iter (fun namespace -> List.iter (fun name ->
      let collection = List.mem operation ["create";"deletecollection"] in
      let read = List.mem operation ["list";"watch"] in
      let valid_name = I.dns_subdomain name in
      let expected = List.mem operation allowed && namespace="" &&
        (if collection then name="" else if read then name="" || valid_name else valid_name) in
      let r = request group resource subresource operation namespace name in
      check ("domain: "^resource^"/"^operation) (Ir.matches (K.Lower.domain s) r=expected);
      check "concrete grant agrees with bounded domain" (Ir.possibly_allows all r=expected);
      check "RoleBinding cannot grant cluster controller requests" (not (Ir.possibly_allows local r));
      check "evaluation adapter enforces same domain"
        (Result.is_ok (K.Evaluate.requests s (evaluation group resource subresource operation namespace name))=expected))
      ["";"object";"widgets.acme.example";"Bad";"*";String.make 254 'a'])
      ["";"team-a"]) (initial@["apply-existing";"apply-missing";"update-existing";"update-missing";"connect";"GET"]);
    List.iter (fun operation ->
      let names = if List.mem operation ["create";"deletecollection"] then `Null else strings ["widgets.acme.example"] in
      let selected = scope ~group ~resource ~subresource ~operation ~namespace:`Null ~names () in
      check "supported controller clause accepted" (Result.is_ok (parse (contract ~allow:selected ())));
      List.iter (fun namespace ->
        check "cluster scope rejects namespace selectors"
          (Result.is_error (parse (contract ~allow:(set "namespace" namespace selected) ()))))
        [`String "team-a";`O ["include",strings ["team-a"]];`O ["exclude",strings []]]) allowed) entries;
  List.iter (fun version -> check "unknown/noninteger contract schema rejected"
    (Result.is_error (parse (replace "schema_version" version (contract ())))))
    [`Number "11";`Number "10.0";`String "10";`Null];
  List.iter (fun (group,resource) ->
    check "native controller API cannot enter custom catalogue"
      (Result.is_error (K.Catalogue.of_string (I.json (`A [`O ["api_group",`String group;
        "resource",`String resource;"scope",`String "Cluster";"subresources",strings []]])))))
    ["admissionregistration.k8s.io","validatingwebhookconfigurations";
     "apiextensions.k8s.io","customresourcedefinitions";
     "authorization.k8s.io","subjectaccessreviews";"authentication.k8s.io","tokenreviews"]

let matching () =
  let s = spec (contract ()) in
  List.iter (fun (group,resource,subresource,operations) -> List.iter (fun operation ->
    let name = if List.mem operation ["create";"deletecollection"] then "" else "widgets.acme.example" in
    let r = request group resource subresource operation "" name in
    let combined = resource ^ if subresource="" then "" else "/"^subresource in
    let trials = [
      rule ~verbs:[operation] ~groups:[group] [combined],true;
      rule ~verbs:[operation] ~groups:["wrong.example"] [combined],false;
      rule ~verbs:["*not-a-verb*"] ~groups:[group] [combined],false;
      rule ~verbs:[operation] ~groups:[group] ~names:[name] [combined],true;
      rule ~verbs:[operation] ~groups:[group] ~names:["other.example"] [combined],false;
      rule ~verbs:[operation] ~groups:[group] ~names:["*"] [combined],false;
      rule ~groups:["*"] ["*"],true;
      rule ~groups:[group] [resource^"/*"],false] in
    List.iter (fun (rule,wanted) ->
      let p = policy s (snapshot (grant "trial" [rule])) in
      check "exact group/resource/operation/name grant" (Ir.possibly_allows p r=wanted)) trials;
    let group_grant = policy s (snapshot (grant ~subject:"controller-team" ~subject_kind:"Group"
      "group" [rule ~groups:[group] [combined]])) in
    check "frozen group grants" (Ir.possibly_allows group_grant r);
    check "unrelated identity does not inherit group grant"
      (not (Ir.possibly_allows group_grant {r with principal=Authenticated "reviewer"}));
    if subresource<>"" then begin
      let p = policy s (snapshot (grant "sub" [rule ~groups:[group] ["*/"^subresource]])) in
      check "native wildcard exact subresource" (Ir.possibly_allows p r);
      let p = policy s (snapshot (grant "base" [rule ~groups:[group] [resource]])) in
      check "base resource does not grant status" (not (Ir.possibly_allows p r))
    end) operations) entries

let outcome = function Report.Proved -> "proved" | Violated _ -> "violated"
  | Unknown _ -> "unknown" | Vacuous -> "vacuous" | Inconsistent _ -> "inconsistent"
let from_ce (ce : Report.counterexample) : Ir.request =
  {principal=Authenticated ce.principal;action=ce.action;resource=ce.path;context=[];
   source=0l;host="";scheme="";sni="";object_request=ce.object_request}
let verify label s source wanted =
  let result = K.Verify.run s source in
  check (label^": expected "^wanted^", got "^outcome result.result) (outcome result.result=wanted);
  check "frozen contract retained" (result.frozen_spec=Some (K.Contract_spec.frozen_spec s));
  (match result.result with
   | Report.Violated ce ->
     let p = policy s source in
     let clause = List.find (fun c -> Contract.name c=(Option.get result.clause).name)
       (K.Contract_spec.to_contract s).clauses in
     check "typed contract witness validated" (Witness.clause p clause (from_ce ce));
     check "source grants explained" (ce.granting_rules=K.Lower.granting_rules p (from_ce ce))
   | _ -> ()); result
let compare label s before after wanted =
  let result = K.Verify.compare_with_trace s ~before ~after in
  check (label^": expected "^wanted^", got "^outcome result.report.result) (outcome result.report.result=wanted);
  check "comparison candidate requirements proved" ((Option.get result.candidate_report).result=Report.Proved);
  (match result.report.result with
   | Report.Violated ce ->
     check "preservation phase" ((Option.get result.report.clause).kind=Report.Must_preserve);
     check "typed outside-approved-scope difference" (Witness.decision_difference
       ~when_:(Ir.Not (K.Contract_spec.approved_changes s))
       (policy s before) (policy s after) (from_ce ce))
   | _ -> ()); result

let workflows directory =
  let source name = read (Filename.concat directory (name^".json")) in
  let s = ok (K.Contract_spec.of_string (source "contract")) in
  List.iter (fun (name,wanted) -> ignore (verify name s (source name) wanted))
    ["unsafe","violated";"repaired","proved";"deny-all","violated";
     "leftover-group","violated";"named-review","violated";"operator-regression","proved"];
  ignore (compare "minimal repair" s (source "unsafe") (source "repaired") "proved");
  ignore (compare "reviewer absent from clauses is preserved" s (source "unsafe") (source "operator-regression") "violated");
  let needed = grant "needed" [rule ~verbs:["get"] ~groups:[""] ~names:["settings"] ["configmaps"]] in
  let review = grant ~subject:"reviewer" "review" [rule ~verbs:["create"] ~groups:["authorization.k8s.io"] ["subjectaccessreviews"]] in
  let before = snapshot (needed@review) and after = snapshot needed in
  ignore (compare "schema9 excludes review permission changes" (spec (contract ~version:9 ())) before after "proved");
  ignore (compare "schema10 preserves unused review class" (spec (contract ())) before after "violated");
  let approved = scope ~subject:"reviewer" ~group:"authorization.k8s.io" ~resource:"subjectaccessreviews"
      ~operation:"create" ~namespace:`Null ~names:`Null () in
  ignore (compare "explicit review scope permits only that change"
    (spec (contract ~changes:[approved] ())) before after "proved");
  let new_grant = snapshot (needed @ grant "added" [rule ~verbs:["get"] ~groups:["apiextensions.k8s.io"] ["customresourcedefinitions"]]) in
  ignore (compare "new access absent from clauses is preserved" (spec (contract ())) after new_grant "violated")

let () =
  if Array.length Sys.argv<>3 then failwith "expected legacy contract and controller workflow paths";
  legacy Sys.argv.(1); domains (); matching (); workflows Sys.argv.(2);
  Printf.printf "controller API library: %d checks passed\n" !checks
