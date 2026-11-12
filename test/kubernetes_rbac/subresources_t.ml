open Soundcheck_core
module K = Soundcheck_kubernetes_rbac
module I = K.Input

let checks = ref 0
let check label yes = incr checks; if not yes then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let strings xs = `A (List.map (fun x -> `String x) xs)
let set key value fields = (key,value) :: List.remove_assoc key fields
let field key = function `O xs -> List.assoc key xs | _ -> failwith "object expected"
let bases = [
  "","configmaps","configmaps",false; "","secrets","secrets",false;
  "","pods","pods",false; "","services","services",false;
  "","endpoints","endpoints",false; "","nodes","nodes",true;
  "apps","deployments","deployments.apps",false;
  "discovery.k8s.io","endpointslices","endpointslices.discovery.k8s.io",false]
(* Independently frozen from Kubernetes v1.34.0 storage registration, REST
   interfaces, RequestInfo and RuleAllows, not from Soundcheck's catalogue.
   GET exec is initial get authorization only; its further create check is
   outside this model. Token create is named, unlike base-resource create. *)
let added = [
  "","pods","log","pods/log",false,["get"];
  "","pods","exec","pods/exec",false,["get";"create"];
  "","serviceaccounts","token","serviceaccounts/token",false,["create"];
  "","pods","status","pods/status",false,["get";"update";"patch"];
  "","services","status","services/status",false,["get";"update";"patch"];
  "","nodes","status","nodes/status",true,["get";"update";"patch"];
  "apps","deployments","status","deployments/status.apps",false,["get";"update";"patch"];
  "apps","deployments","scale","deployments/scale.apps",false,["get";"update";"patch"]]
let verbs = ["get";"list";"watch";"update";"patch";"delete";"create";"deletecollection"]
let scope ?(subject="app") ?(verb="get") ?(group="") ?(resource="configmaps")
    ?(subresource="") ?(ns=`String "team-a") ?(names=strings ["settings"]) () =
  ["subject",`String subject;"verb",`String verb;"api_group",`String group;
   "resource",`String resource;"subresource",`String subresource;"namespace",ns;"names",names]
let contract ?(version=7) ?(allow=scope ())
    ?(deny=scope ~resource:"secrets" ~names:`Null ()) ?(changes=[]) () =
  let fields xs = if version>=7 then xs else
    let xs=List.remove_assoc "subresource" xs in
    if version=1 then List.remove_assoc "verb" (List.remove_assoc "api_group" xs)
    else if version<5 then List.remove_assoc "api_group" xs else xs in
  `O ["schema_version",`Number (string_of_int version);"kind",`String K.Contract_spec.kind;
    "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
      "identities",`A [`O ["username",`String "app";"groups",strings ["operators"]];
                       `O ["username",`String "unused";"groups",strings []]]];
    "clauses",`A [
      `O (["name",`String "required";"kind",`String "must_allow"] @ fields allow);
      `O (["name",`String "forbidden";"kind",`String "must_not_grant"] @ fields deny)];
    "change_scope",`A (List.map (fun xs -> `O (fields xs)) changes)]
let parse value = K.Contract_spec.of_string (I.json value)
let spec value = ok (parse value)
let rule ?(verbs=["*"]) ?(groups=[""]) ?(names=[]) resources =
  `O ["verbs",strings verbs;"apiGroups",strings groups;"resources",strings resources;
      "resourceNames",strings names]
let grant ?(binding="ClusterRoleBinding") ?(role="ClusterRole") ?(subject="app") name rules =
  let api="rbac.authorization.k8s.io" in
  let metadata kind = `O (["name",`String name] @
    if kind="Role" || kind="RoleBinding" then ["namespace",`String "team-a"] else []) in
  [`O ["apiVersion",`String (api^"/v1");"kind",`String role;"metadata",metadata role;"rules",`A rules];
   `O ["apiVersion",`String (api^"/v1");"kind",`String binding;"metadata",metadata binding;
     "roleRef",`O ["apiGroup",`String api;"kind",`String role;"name",`String name];
     "subjects",`A [`O ["kind",`String "User";"apiGroup",`String api;"name",`String subject]]]]
let snapshot items = I.json (`O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items])
let policy s source = K.Lower.policy s (ok (K.Snapshot.of_string source))
let request ?(subject="app") kind verb namespace name : Ir.request =
  {principal=Authenticated subject;action=verb;resource="";context=[];source=0l;host="";scheme="";sni="";
   object_request=Some {namespace;resource_kind=kind;name}}
let request_json ?(groups=["operators"]) ?(subresource="") ?(resource_request=true)
    group resource verb namespace name =
  `O ["id",`String "request";"username",`String "app";"groups",strings groups;
    "apiGroup",`String group;"resource",`String resource;"verb",`String verb;
    "namespace",`String namespace;"name",`String name;
    "subresource",`String subresource;"resourceRequest",`Bool resource_request]
let evaluate s row = K.Evaluate.requests s (I.json (`A [row]))
let outcome = function Report.Proved -> "proved" | Violated _ -> "violated"
  | Vacuous -> "vacuous" | Inconsistent _ -> "inconsistent" | Unknown _ -> "unknown"
let from_ce (ce:Report.counterexample) =
  let c=Option.get ce.object_request in request ~subject:ce.principal c.resource_kind ce.action c.namespace c.name
let verify label s source expected =
  let report=K.Verify.run s source in
  check (label^" verdict") (outcome report.result=expected);
  check (label^" frozen identity") (report.frozen_spec=Some (K.Contract_spec.frozen_spec s));
  (match report.result with
   | Report.Violated ce ->
     let p=policy s source and r=from_ce ce in
     let clause=List.find (fun c -> Contract.name c=(Option.get report.clause).name)
       (K.Contract_spec.to_contract s).clauses in
     check (label^" witness obligation") (Witness.clause p clause r);
     check (label^" request belongs to frozen domain") (Ir.matches (K.Lower.domain s) r);
     check (label^" grant provenance") (ce.granting_rules=K.Lower.granting_rules p r)
   | _ -> ()); report
let compare label s before after expected =
  let result=K.Verify.compare_with_trace s ~before ~after in
  check (label^" verdict") (outcome result.report.result=expected);
  check (label^" candidate contract independently proved")
    ((Option.get result.candidate_report).result=Report.Proved);
  (match result.report.result with
   | Report.Violated ce ->
     check (label^" preservation phase") ((Option.get result.report.clause).kind=Report.Must_preserve);
     check (label^" outside approved scope")
       (Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes s))
          (policy s before) (policy s after) (from_ce ce));
     check (label^" frozen-domain witness") (Ir.matches (K.Lower.domain s) (from_ce ce))
   | _ -> ()); result.report

let () =
  (* Captured from a fresh untouched 1c0923a build before schema 7 work.
     Full baseline artifacts retained locally outside the repository. *)
  List.iter (fun (version,hash) -> check "old profile bytes stay frozen"
    (Sha256.string (K.Assurance.profile_json ~version ())=hash)) [
    1,"31230a9fb3e62798f74e50b77eb61fb7554d8c9dbd511c1b7f2370a395f07b3b";
    2,"bdaa6e06babb84cbf69fe060bc84ea030b3528ef9f8b0e57548b1c9cc4ac4455";
    3,"de7842a1f531b9b87b408689fd0e94a9c3cf15edd58cbb0b50c98c9975e35d03";
    4,"dc66d39ebc0986f216671974f4da636cf5ad511c0f7d998701c5b4f6815d67e7";
    5,"33702f3193261a8f6b6150291135b23ca3e38280f708b4bf30c47167e90f9af7";
    6,"ea4f7e094c800f68fe02703828bc2a03a02269e3cfc855a622af296ad77050b3"];
  let context=`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
    "identities",`A [`O ["username",`String "unused";"groups",strings []];
                     `O ["username",`String "app";"groups",strings ["z";"a"]]]] in
  let old allow deny changes = match contract ~version:6 ~allow ~deny ~changes () with
    | `O fields -> spec (`O (set "context" context fields)) | _ -> assert false in
  let namespace_set=`O ["include",strings ["team-b";"team-a"]]
  and namespace_complement=`O ["exclude",strings ["team-b";"team-a"]] in
  let compound=old
    (scope ~verb:"list" ~group:"apps" ~resource:"deployments" ~ns:namespace_set
      ~names:(`O ["exclude",strings ["z";"a"];"include_empty",`Bool true]) ())
    (scope ~verb:"deletecollection" ~resource:"nodes" ~ns:`Null ~names:(`O ["empty",`Bool true]) ())
    [scope ~subject:"unused" ~verb:"create" ~resource:"pods" ~ns:namespace_complement ~names:`Null ();
     scope ~verb:"patch" ~group:"apps" ~resource:"deployments" ~ns:namespace_complement ~names:(strings ["z";"a"]) ();
     scope ~verb:"patch" ~group:"apps" ~resource:"deployments"
       ~ns:(`O ["exclude",strings ["team-a";"team-b"]]) ~names:(strings ["a";"z"]) ()] in
  check "compound schema-6 canonical identity remains frozen"
    (Sha256.string (K.Contract_spec.canonical compound)="b6eeb580f66e44e738b6b2c589c46a9db934ad0ae31fc53044c53c2ee8f3d8d5"
     && List.length (K.Contract_spec.changes compound)=2);
  let collection=old
    (scope ~verb:"create" ~group:"apps" ~resource:"deployments" ~ns:namespace_set ~names:(`O ["empty",`Bool true]) ())
    (scope ~resource:"nodes" ~ns:`Null ~names:(`O ["exclude",strings ["node-b";"node-a"];"include_empty",`Bool false]) ())
    [scope ~subject:"unused" ~verb:"watch" ~group:"discovery.k8s.io" ~resource:"endpointslices" ~ns:`Null ~names:(`O ["empty",`Bool true]) ();
     scope ~verb:"deletecollection" ~resource:"services" ~ns:namespace_complement ~names:`Null ()] in
  check "schema-6 collection scopes keep their canonical identity"
    (Sha256.string (K.Contract_spec.canonical collection)="b4ab6f329407dc7e2f9cc753b34554984ce19791d67cc22a93ef6aac0be5cf03");
  let s=spec (contract ()) in
  check "schema 7 has an explicit opt-in assurance profile"
    (K.Assurance.id_for_version 7="kubernetes-rbac-v1.34-subresources-v1");
  check "independent approved catalogue contains eight entries and nineteen operations"
    (List.length added=8 && List.fold_left (fun n (_,_,_,_,_,vs) -> n+List.length vs) 0 added=19);
  List.iter (fun (group,raw,kind,_) ->
    let entry=Option.get (K.Resource_domain.find ~version:7 ~api_group:group ~resource:raw) in
    check "base lookup remains base-only in schema 7"
      (entry.subresource="" && K.Resource_domain.kind entry=kind)) bases;
  List.iter (fun (group,raw,sub,kind,_,_) ->
    let entry=Option.get (K.Resource_domain.find_subresource ~version:7 ~api_group:group ~resource:raw ~subresource:sub) in
    check "subresource kind decodes only through the exact catalogue"
      (K.Resource_domain.kind entry=kind && K.Resource_domain.of_kind ~version:7 kind=Some entry);
    check "schema6 has no hidden subresource lookup"
      (K.Resource_domain.find_subresource ~version:6 ~api_group:group ~resource:raw ~subresource:sub=None)) added;
  List.iter (fun selected ->
    check "schema7 requires the empty subresource for base clauses"
      (Result.is_error (parse (contract ~allow:selected ())));
    check "schema7 requires the empty subresource for base approved scopes"
      (Result.is_error (parse (contract ~changes:[selected] ()))))
    [scope () |> List.remove_assoc "subresource";scope () |> set "subresource" `Null];
  let identity sub=spec (contract ~changes:[scope ~verb:"patch" ~group:"apps"
    ~resource:"deployments" ~subresource:sub ()] ()) in
  check "frozen identity distinguishes status from scale with identical other coordinates"
    (K.Contract_spec.canonical (identity "status")<>K.Contract_spec.canonical (identity "scale"));
  List.iter (fun version ->
    let old=spec (contract ~version ()) in
    List.iter (fun (group,raw,sub,kind,cluster,allowed) -> List.iter (fun verb ->
      let ns=if cluster then "" else "team-a" in
      check "schemas 1-6 cannot acquire subresource requests"
        (not (Ir.matches (K.Lower.domain old) (request kind verb ns "worker")));
      check "schemas 1-6 reject concrete subresources"
        (Result.is_error (evaluate old (request_json ~subresource:sub group raw verb ns "worker")))) allowed) added;
    let source=contract ~version () in
    let with_subresource=match source with `O fields ->
      let clauses=match field "clauses" source with `A (`O first::rest) ->
        `A (`O (set "subresource" (`String "") first)::rest) | _ -> assert false in
      `O (set "clauses" clauses fields) | _ -> assert false in
    check "even empty subresource fields require schema 7" (Result.is_error (parse with_subresource));
    let with_change=match source with `O fields ->
      let change=scope () |> (fun xs -> if version=1 then List.remove_assoc "verb" xs else xs)
        |> (fun xs -> if version<5 then List.remove_assoc "api_group" xs else xs) in
      `O (set "change_scope" (`A [`O change]) fields) | _ -> assert false in
    check "old change scopes reject even an empty explicit subresource" (Result.is_error (parse with_change))) [1;2;3;4;5;6];
  let old=spec (contract ~version:6 ()) in
  List.iter (fun (_,_,kind,_) -> List.iter (fun verb -> List.iter (fun ns -> List.iter (fun name ->
    check "schema 7 preserves every existing base request domain"
      (Ir.matches (K.Lower.domain old) (request kind verb ns name)=
       Ir.matches (K.Lower.domain s) (request kind verb ns name))) ["";"worker";"Bad";"*"])
    ["";"team-a";"future";"Bad"]) verbs) bases;
  List.iter (fun (group,raw,sub,kind,cluster,allowed) ->
    List.iter (fun verb -> List.iter (fun ns -> List.iter (fun name ->
      let expected=List.mem verb allowed && (if cluster then ns="" else List.mem ns ["team-a";"future"])
        && List.mem name ["worker";"future"] in
      let r=request kind verb ns name in
      check "exact approved subresource operation domain" (Ir.matches (K.Lower.domain s) r=expected);
      let concrete=evaluate s (request_json ~subresource:sub group raw verb ns name) in
      check "concrete adapter rejects non-route operation/name/scope combinations" (Result.is_ok concrete=expected);
      if expected then check "concrete identity is injective and uses parent name"
        ((List.hd (ok concrete)).request=r)) ["";"worker";"future";"Bad";"*"])
      ["";"team-a";"future";"Bad"]) (verbs@["connect";"proxy"]);
    List.iter (fun verb ->
      let ns=if cluster then `Null else `String "team-a" in
      let selected=scope ~verb ~group ~resource:raw ~subresource:sub ~ns ~names:`Null () in
      List.iter (fun names ->
        let selected=set "names" names selected in
        check "all-named, named sets and named complements are supported in clauses"
          (Result.is_ok (parse (contract ~allow:selected ())));
        check "same named selectors supported in change scopes"
          (Result.is_ok (parse (contract ~changes:[selected] ()))))
        [`Null;strings ["worker";"future"];
         `O ["exclude",strings ["worker"];"include_empty",`Bool false]];
      let bad=[List.remove_assoc "subresource" selected;
        set "subresource" `Null selected;set "subresource" (`String "*") selected;
        set "subresource" (`String (sub^"/nested")) selected;
        set "resource" (`String (raw^"/"^sub)) selected;
        List.remove_assoc "api_group" selected;
        set "names" (`O ["empty",`Bool true]) selected;
        set "names" (strings [""]) selected;set "names" (strings []) selected;
        set "names" (`O ["exclude",strings [];"include_empty",`Bool true]) selected;
        set "namespace" (`String "") selected] in
      List.iter (fun selected ->
        check "invalid subresource clause fails closed" (Result.is_error (parse (contract ~allow:selected ())));
        check "invalid subresource approved change fails closed" (Result.is_error (parse (contract ~changes:[selected] ())))) bad;
      List.iter (fun verb -> if not (List.mem verb allowed) then
        let invalid=set "verb" (`String verb) selected in
        check "contract cannot authorize an uninstalled operation"
          (Result.is_error (parse (contract ~allow:invalid ())));
        check "approved changes cannot name an uninstalled operation"
          (Result.is_error (parse (contract ~changes:[invalid] ())))) verbs;
      List.iter (fun ns ->
        check "namespace selector availability follows the parent resource"
          (Result.is_ok (parse (contract ~allow:(set "namespace" ns selected) ()))=not cluster))
        [`O ["include",strings ["team-b";"team-a"]];`O ["exclude",strings ["team-b"]]];
      check "only cluster subresources accept a null namespace"
        (Result.is_ok (parse (contract ~allow:(set "namespace" `Null selected) ()))=cluster)) allowed) added;
  List.iter (fun (group,raw,sub,verb,ns) ->
    check "unregistered resource/group/subresource combinations are outside the domain"
      (Result.is_error (evaluate s (request_json ~subresource:sub group raw verb ns "worker")));
    check "unregistered combinations cannot become frozen clauses"
      (Result.is_error (parse (contract ~allow:(scope ~group ~resource:raw ~subresource:sub ~verb
        ~ns:(if ns="" then `Null else `String ns) ()) ())))) [
      "","configmaps","status","get","team-a";"","secrets","status","get","team-a";
      "","endpoints","status","get","team-a";"discovery.k8s.io","endpointslices","status","get","team-a";
      "","pods","scale","get","team-a";"","pods","attach","get","team-a";
      "","pods","portforward","create","team-a";"","pods","eviction","create","team-a";
      "","pods","proxy","get","team-a";"","pods","ephemeralcontainers","patch","team-a";
      "","pods","resize","patch","team-a";"","serviceaccounts","","create","team-a";
      "autoscaling","deployments","scale","get","team-a";
      "apps","deployments.apps","scale","get","team-a"];
  (* Native resource matcher: only '*' and '*/<literal subresource>' have
     special meaning. Native validation accepts misleading strings such as
     pods/* and */*, but they do not match ordinary subresource requests. *)
  let cases=[
    "whole wildcard",["*"],["*"],[],(fun _ _ _ _ -> true);
    "exact pod status",[""],["pods/status"],[],(fun group raw sub _ -> group="" && raw="pods" && sub="status");
    "base pods only",[""],["pods"],[],(fun _ _ _ _ -> false);
    "parent-star is literal",["*"],["pods/*"],[],(fun _ _ _ _ -> false);
    "double-star is literal",["*"],["*/*"],[],(fun _ _ _ _ -> false);
    "status suffix wildcard",["*"],["*/status"],[],(fun _ _ sub _ -> sub="status");
    "scale suffix wildcard",["apps"],["*/scale"],[],(fun group _ sub _ -> group="apps" && sub="scale");
    "wrong scale group",["autoscaling"],["*/scale"],[],(fun _ _ _ _ -> false);
    "core status wildcard",[""],["*/status"],[],(fun group _ sub _ -> group="" && sub="status");
    "exec exact parent name",[""],["pods/exec"],["worker"],(fun group raw sub name -> group="" && raw="pods" && sub="exec" && name="worker");
    "token exact parent name",[""],["serviceaccounts/token"],["worker"],(fun group raw sub name -> group="" && raw="serviceaccounts" && sub="token" && name="worker");
    "literal star name",["*"],["*"],["*"],(fun _ _ _ _ -> false);
    "literal empty name",["*"],["*"],[""],(fun _ _ _ _ -> false);
    "mixed unknown rule does not erase valid grant",["*"],["not-a-resource";"*/status"],[],(fun _ _ sub _ -> sub="status")] in
  List.iter (fun (label,groups,resources,names,expected) ->
    let p=policy s (snapshot (grant "test" [rule ~groups ~names resources])) in
    List.iter (fun (group,raw,sub,kind,cluster,allowed) -> List.iter (fun verb ->
      List.iter (fun name -> let r=request kind verb (if cluster then "" else "team-a") name in
        let answer=expected group raw sub name in
        check (label^" native resource/name matching")
          (Ir.possibly_allows p r=answer && Ir.definitely_allows p r=answer)) ["worker";"other"]) allowed) added) cases;
  List.iter (fun (role,binding) ->
    let p=policy s (snapshot (grant ~role ~binding "local" [rule ~groups:["*"] ["*"]])) in
    List.iter (fun (_,_,_,kind,cluster,allowed) -> List.iter (fun verb ->
      List.iter (fun ns -> let r=request kind verb ns "worker" in
        let expected=not cluster && ns="team-a" in
        check "RoleBinding cannot grant cluster subresources or another namespace"
          (Ir.possibly_allows p r=expected && Ir.definitely_allows p r=expected))
        (if cluster then [""] else ["team-a";"team-b"])) allowed) added)
    ["Role","RoleBinding";"ClusterRole","RoleBinding"];
  let selected=scope ~verb:"create" ~resource:"pods" ~subresource:"exec" ~ns:namespace_set
    ~names:(`O ["exclude",strings ["worker"];"include_empty",`Bool false]) () in
  let scoped=spec (contract ~changes:[selected;selected] ()) in
  let condition=K.Contract_spec.approved_changes scoped in
  check "subresource selectors normalize and deduplicate without weakening scope"
    (List.length (K.Contract_spec.changes scoped)=1 && K.Contract_spec.canonical scoped=
      K.Contract_spec.canonical (ok (K.Contract_spec.of_string (K.Contract_spec.canonical scoped))));
  List.iter (fun (kind,verb,ns,name,expected) -> check "named exec scope does not absorb base create or another subresource"
    (Ir.matches condition (request kind verb ns name)=expected)) [
    "pods/exec","create","team-a","other",true;"pods/exec","create","team-b","other",true;
    "pods/exec","create","team-c","other",false;"pods/exec","create","team-a","worker",false;
    "pods/exec","create","team-a","",false;"pods","create","team-a","",false;
    "pods/log","get","team-a","other",false;"pods/exec","get","team-a","other",false];
  let exec=scope ~verb:"create" ~resource:"pods" ~subresource:"exec" ~names:(strings ["worker"]) ()
  and logs=scope ~resource:"pods" ~subresource:"log" ~names:(strings ["worker"]) () in
  let workflow=spec (contract ~allow:logs ~deny:exec ~changes:[exec] ()) in
  let read_logs=grant ~binding:"RoleBinding" "logs" [rule ~verbs:["get"] ~names:["worker"] ["pods/log"]]
  and execute=grant ~binding:"RoleBinding" "exec" [rule ~verbs:["create"] ~names:["worker"] ["pods/exec"]] in
  ignore (verify "keep log access while forbidding exec" workflow (snapshot read_logs) "proved");
  ignore (verify "deny all fails named subresource functionality" workflow (snapshot []) "violated");
  let unsafe=verify "named exec grant violates frozen access rule" workflow (snapshot (read_logs@execute)) "violated" in
  check "named create witness uses the parent Pod name"
    (match unsafe.result with Violated ce -> ce.action="create" && (Option.get ce.object_request).name="worker"
      && (Option.get ce.object_request).resource_kind="pods/exec" | _ -> false);
  ignore (compare "exact exec repair preserves logs" workflow (snapshot (read_logs@execute)) (snapshot read_logs) "proved");
  let common=grant ~binding:"RoleBinding" "config" [rule ~verbs:["get"] ~names:["settings"] ["configmaps"]] in
  List.iter (fun (group,raw,sub,kind,cluster,allowed) -> List.iter (fun verb ->
    let binding=if cluster then "ClusterRoleBinding" else "RoleBinding" in
    let extra=grant ~binding ~subject:"unused" "unmentioned" [rule ~groups:[group] ~verbs:[verb] ~names:["worker"] [raw^"/"^sub]] in
    let before=snapshot (common@extra) and after=snapshot common in
    let report=compare "all nineteen unmentioned subresource operations are preserved" s before after "violated" in
    check "preservation witness identifies frozen unused identity and exact endpoint"
      (match report.result with Violated ce -> ce.principal="unused" && ce.action=verb &&
        let c=Option.get ce.object_request in c.resource_kind=kind && c.name="worker" &&
        c.namespace=(if cluster then "" else "team-a") | _ -> false)) allowed) added;
  let before=snapshot (common @ grant ~subject:"unused" "extra"
    [rule ~verbs:["create"] ["pods"];rule ~verbs:["create"] ~names:["worker"] ["pods/exec"]]) in
  let after=snapshot common in
  let base_change=scope ~subject:"unused" ~verb:"create" ~resource:"pods" ~names:`Null
    ~ns:(`O ["exclude",strings []]) ()
  and sub_change=scope ~subject:"unused" ~verb:"create" ~resource:"pods" ~subresource:"exec" ~names:`Null
    ~ns:(`O ["exclude",strings []]) () in
  let check_remaining changes kind =
    let report=compare "base and subresource changes are disjoint" (spec (contract ~changes ())) before after "violated" in
    check "unapproved sibling operation remains protected"
      (match report.result with Violated ce -> (Option.get ce.object_request).resource_kind=kind | _ -> false) in
  check_remaining [base_change] "pods/exec";check_remaining [sub_change] "pods";
  ignore (compare "explicit approval of both disjoint classes permits repair"
    (spec (contract ~changes:[base_change;sub_change] ())) before after "proved");
  ignore (compare "schema 6 ignores only the new subresource domain" (spec (contract ~version:6 ()))
    (snapshot (common @ grant ~subject:"unused" "exec" [rule ~verbs:["create"] ["pods/exec"]]))
    (snapshot common) "proved");
  Printf.printf "RBAC subresources: %d checks passed\n" !checks
