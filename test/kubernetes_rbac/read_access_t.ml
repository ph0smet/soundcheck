open Soundcheck_core
module K = Soundcheck_kubernetes_rbac

let count = ref 0
let check label value = incr count; if not value then failwith label
let get = function Ok x -> x | Error reason -> failwith reason
let strings xs = `A (List.map (fun x -> `String x) xs)
let replace key value = function
  | `O fields -> `O (List.map (fun (k,v) -> k,if k=key then value else v) fields)
  | _ -> assert false
let scope ?(verb="get") ?(ns=`String "team") ?(resource="configmaps") ?(names=`Null) () =
  ["subject",`String "frontend";"verb",`String verb;"namespace",ns;
   "resource",`String resource;"names",names]
let contract ?(version=2) ?(allow=scope ())
    ?(deny=scope ~resource:"secrets" ()) ?(changes=[]) () =
  let fields xs = if version=1 then List.remove_assoc "verb" xs else xs in
  `O ["schema_version",`Number (string_of_int version);"kind",`String K.Contract_spec.kind;
      "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
        "identities",`A [`O ["username",`String "frontend";"groups",strings ["readers"]]]];
      "clauses",`A [
        `O (["name",`String "required";"kind",`String "must_allow"] @ fields allow);
        `O (["name",`String "forbidden";"kind",`String "must_not_grant"] @ fields deny)];
      "change_scope",`A (List.map (fun s -> `O (fields s)) changes)]
let spec value = get (K.Contract_spec.of_string (K.Input.json value))
let rule ?(verbs=["get";"list";"watch"]) ?(names=[]) ?(groups=[""]) resource =
  `O ["verbs",strings verbs;"apiGroups",strings groups;
      "resources",strings [resource];"resourceNames",strings names]
let snapshot ?(cluster=false) ?(group=false) rules =
  let role_kind,binding_kind = if cluster then "ClusterRole","ClusterRoleBinding"
    else "Role","RoleBinding" in
  let metadata = `O (["name",`String "reader"] @
                    if cluster then [] else ["namespace",`String "team"]) in
  let api = "rbac.authorization.k8s.io" in
  K.Input.json (`O ["apiVersion",`String "v1";"kind",`String "List";"items",`A [
    `O ["apiVersion",`String (api ^ "/v1");"kind",`String role_kind;
        "metadata",metadata;"rules",`A rules];
    `O ["apiVersion",`String (api ^ "/v1");"kind",`String binding_kind;
        "metadata",metadata;"roleRef",`O ["apiGroup",`String api;"kind",`String role_kind;"name",`String "reader"];
        "subjects",`A [`O ["kind",`String (if group then "Group" else "User");
          "apiGroup",`String api;"name",`String (if group then "readers" else "frontend")]]]]])
let policy spec source = K.Lower.policy spec (get (K.Snapshot.of_string source))
let request ?(resource="configmaps") verb ns name : Ir.request =
  {principal=Ir.Authenticated "frontend";action=verb;resource="";context=[];
   source=0l;host="";scheme="";sni="";
   object_request=Some {namespace=ns;resource_kind=resource;name}}
let request_json (r:Ir.request) =
  let obj = Option.get r.object_request in
  K.Input.json (`A [`O ["id",`String "one";"username",`String "frontend";
    "groups",strings ["readers"];"verb",`String r.action;"apiGroup",`String "";
    "resourceRequest",`Bool true;"subresource",`String "";
    "namespace",`String obj.namespace;"resource",`String obj.resource_kind;"name",`String obj.name]])
let result = function
  | Report.Proved -> "proved" | Violated _ -> "violated" | Unknown _ -> "unknown"
  | Vacuous -> "vacuous" | Inconsistent _ -> "inconsistent"
let verify label spec source wanted =
  let report = K.Verify.run spec source in
  check label (result report.result = wanted);
  check (label ^ " profile") ((Option.get report.assurance).profile =
      K.Assurance.id_for_version (K.Contract_spec.version spec));
  (match report.result with
   | Report.Violated ce ->
     let r = request ~resource:(Option.get ce.object_request).resource_kind
       ce.action (Option.get ce.object_request).namespace (Option.get ce.object_request).name in
     check (label ^ " in-domain witness") (Ir.matches (K.Lower.domain spec) r);
     check (label ^ " grant provenance") (ce.granting_rules = K.Lower.granting_rules (policy spec source) r)
   | _ -> ()); report

let () =
  let v1 = spec (contract ~version:1 ()) in
  let v2 = spec (contract ()) in
  List.iter (fun spec ->
    let source = K.Contract_spec.canonical spec in
    check "canonical roundtrip" (K.Contract_spec.canonical (spec |> K.Contract_spec.canonical |> K.Contract_spec.of_string |> get)=source);
    check "frozen version" ((K.Contract_spec.frozen_spec spec).schema_version=K.Contract_spec.version spec)) [v1;v2];
  List.iter (fun verb -> List.iter (fun ns -> List.iter (fun name ->
      let r = request verb ns name in
      let expected = (ns="team" || (ns="" && verb<>"get"))
        && (name="settings" || (name="" && verb<>"get"))
        && List.mem verb ["get";"list";"watch"] in
      check "v2 exact request domain" (Ir.matches (K.Lower.domain v2) r=expected);
      check "v2 concrete request validation" (Result.is_ok (K.Evaluate.requests v2 (request_json r))=expected);
      check "v1 domain never widens" (Ir.matches (K.Lower.domain v1) r=(verb="get" && ns="team" && name="settings")))
        ["";"settings";"*";"Bad";"a/b";"bad\000name"])
      ["";"team";"Bad";"a.b"])
    ["get";"list";"watch";"patch"];
  List.iter (fun cluster -> List.iter (fun group ->
    List.iter (fun names ->
      let p = policy v2 (snapshot ~cluster ~group [rule ~names "configmaps"]) in
      List.iter (fun verb -> List.iter (fun ns -> List.iter (fun name ->
        let r = request verb ns name in
        let expected = Ir.matches p.request_domain r && (cluster || ns="team")
          && (names=[] || List.mem name names) in
        check "literal resourceNames and binding scope" (Ir.possibly_allows p r=expected);
        check "exact additive may equals must" (Ir.definitely_allows p r=expected))
        ["";"settings";"other"]) ["";"team";"other"]) ["get";"list";"watch"])
      [[];["settings"];[""];["*"];["";"settings"]]) [false;true]) [false;true];
  List.iter (fun permitted ->
    let p = policy v2 (snapshot [rule ~verbs:[permitted] "configmaps"]) in
    List.iter (fun verb -> check "verbs never leak across operations"
      (Ir.possibly_allows p (request verb "team" "settings")=(verb=permitted || permitted="*")))
      ["get";"list";"watch"]) ["get";"list";"watch";"*";"patch"];
  let wildcard = policy v2 (snapshot ~cluster:true [rule ~verbs:["*"] ~groups:["*"] "*"]) in
  check "wildcards cover all-namespace collection" (Ir.possibly_allows wildcard (request ~resource:"secrets" "watch" "" ""));
  let value = contract () in
  List.iter (fun (label,changed) -> check label
      (Result.is_error (K.Contract_spec.of_string (K.Input.json changed)))) [
    "unknown schema",replace "schema_version" (`Number "3") value;
    "rounded schema",replace "schema_version" (`Number "2.0") value;
    "v2 requires verbs",replace "schema_version" (`Number "2") (contract ~version:1 ());
    "v1 rejects verb fields",replace "schema_version" (`Number "1") value;
    "get rejects all-namespace",contract ~allow:(scope ~ns:`Null ()) ();
    "reject empty namespace string",contract ~allow:(scope ~verb:"list" ~ns:(`String "") ()) ();
    "reject mutation",contract ~allow:(scope ~verb:"create" ()) ();
    "reject wildcard verb",contract ~allow:(scope ~verb:"*" ()) ();
    "reject empty names",contract ~allow:(scope ~verb:"list" ~names:(strings []) ()) ();
    "reject empty name literal",contract ~allow:(scope ~verb:"list" ~names:(strings [""]) ()) ();
    "reject wildcard name literal",contract ~allow:(scope ~verb:"watch" ~names:(strings ["*"]) ()) ();
    "reject duplicate name",contract ~allow:(scope ~names:(strings ["a";"a"]) ()) ();
    "reject unsupported resource",contract ~allow:(scope ~resource:"pods" ()) ();
    "reject unknown scope field",contract ~allow:(("selector",`String "x=y")::scope ()) ();
    "changes need explicit verb",contract ~changes:[List.remove_assoc "verb" (scope ())] ()];
  let read_spec verb names = spec (contract ~allow:(scope ~verb ~names ())
    ~deny:(scope ~verb ~resource:"secrets" ()) ()) in
  let repaired = snapshot [rule "configmaps"] in
  List.iter (fun verb ->
    let s = read_spec verb `Null in
    ignore (verify (verb ^ " complete read") s repaired "proved");
    ignore (verify (verb ^ " empty-name-only is insufficient") s
      (snapshot [rule ~names:[""] "configmaps"]) "violated");
    ignore (verify (verb ^ " leftover Secret grant") s
      (snapshot [rule "configmaps";rule ~verbs:[verb] "secrets"]) "violated");
    ignore (verify (verb ^ " exact-name access") (read_spec verb (strings ["settings"]))
      (snapshot [rule ~names:["settings"] "configmaps"]) "proved")) ["list";"watch"];
  let all_ns = spec (contract ~allow:(scope ~verb:"list" ~ns:`Null ())
      ~deny:(scope ~verb:"watch" ~ns:`Null ~resource:"secrets" ()) ()) in
  ignore (verify "local binding cannot allow all-namespace" all_ns repaired "violated");
  ignore (verify "cluster binding allows all-namespace" all_ns
      (snapshot ~cluster:true [rule "configmaps"]) "proved");
  let conflicting = contract ~allow:(scope ~verb:"list" ()) ~deny:(scope ~verb:"list" ()) () |> spec in
  ignore (verify "overlapping v2 obligations" conflicting repaired "inconsistent");
  let candidate = snapshot [rule ~verbs:["get"] "configmaps"] in
  let compare label s before after wanted =
    let c = K.Verify.compare_with_trace s ~before ~after in
    check label (result c.report.result=wanted);
    if wanted="violated" then begin
      check (label ^ " is preservation") (c.report.property_name="rbac-repair-preservation");
      let ce = match c.report.result with Report.Violated ce -> ce | _ -> assert false in
      let obj = Option.get ce.object_request in
      let r = request ~resource:obj.resource_kind ce.action obj.namespace obj.name in
      check (label ^ " outside change scope") (not (Ir.matches (K.Contract_spec.approved_changes s) r));
      check (label ^ " concrete decision differs")
        (Ir.possibly_allows (policy s before) r <> Ir.possibly_allows (policy s after) r)
    end in
  compare "v1 keeps old get-only preservation" v1 repaired candidate "proved";
  compare "v2 protects list/watch even with get-only clauses" v2 repaired candidate "violated";
  let changes = [scope ~verb:"list" ();scope ~verb:"watch" ()] in
  compare "approved verb changes accepted" (spec (contract ~changes ())) repaired candidate "proved";
  let get_only = spec (contract ~changes:[scope ()] ()) in
  compare "get scope cannot authorize watch changes" get_only repaired candidate "violated";
  let all_ns_changes = List.map (fun verb -> scope ~verb ~ns:`Null ()) ["list";"watch"] in
  compare "all-namespace scope is not a namespace wildcard" (spec (contract ~changes:all_ns_changes ()))
      repaired candidate "violated";
  let broader_changes = List.map (fun verb -> scope ~verb ()) ["get";"list";"watch"] in
  compare "namespace scope does not authorize all-namespace loss" (spec (contract ~changes:broader_changes ()))
    (snapshot ~cluster:true [rule "configmaps"]) repaired "violated";
  Printf.printf "RBAC read access: %d checks passed\n" !count
