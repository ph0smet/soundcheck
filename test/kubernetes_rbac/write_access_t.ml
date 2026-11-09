open Soundcheck_core
module K = Soundcheck_kubernetes_rbac

let checks = ref 0
let check label yes = incr checks; if not yes then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let strings values = `A (List.map (fun value -> `String value) values)
let writes = ["update";"patch";"delete"]
let reads = ["get";"list";"watch"]
let scope ?(verb="get") ?(ns=`String "team") ?(resource="configmaps") ?(names=`Null) () =
  ["subject",`String "app";"verb",`String verb;"namespace",ns;
   "resource",`String resource;"names",names]
let contract ?(version=3) ?(allow=scope ())
    ?(deny=scope ~verb:"update" ~resource:"secrets" ()) ?(changes=[]) () =
  let fields values = if version=1 then List.remove_assoc "verb" values else values in
  `O ["schema_version",`Number (string_of_int version);"kind",`String K.Contract_spec.kind;
      "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
        "identities",`A [`O ["username",`String "app";"groups",strings ["writers"]]]];
      "clauses",`A [
        `O (["name",`String "required";"kind",`String "must_allow"] @ fields allow);
        `O (["name",`String "forbidden";"kind",`String "must_not_grant"] @ fields deny)];
      "change_scope",`A (List.map (fun value -> `O (fields value)) changes)]
let spec value = ok (K.Contract_spec.of_string (K.Input.json value))
let rule ?(verbs=reads) ?(names=[]) ?(groups=[""]) resource =
  `O ["verbs",strings verbs;"apiGroups",strings groups;
      "resources",strings [resource];"resourceNames",strings names]
let snapshot ?(cluster=false) ?(group=false) rules =
  let role,binding = if cluster then "ClusterRole","ClusterRoleBinding" else "Role","RoleBinding" in
  let metadata = `O (["name",`String "access"] @ if cluster then [] else ["namespace",`String "team"]) in
  let api = "rbac.authorization.k8s.io" in
  K.Input.json (`O ["apiVersion",`String "v1";"kind",`String "List";"items",`A [
    `O ["apiVersion",`String (api ^ "/v1");"kind",`String role;"metadata",metadata;"rules",`A rules];
    `O ["apiVersion",`String (api ^ "/v1");"kind",`String binding;"metadata",metadata;
        "roleRef",`O ["apiGroup",`String api;"kind",`String role;"name",`String "access"];
        "subjects",`A [`O ["kind",`String (if group then "Group" else "User");
          "apiGroup",`String api;"name",`String (if group then "writers" else "app")]]]]])
let policy s source = K.Lower.policy s (ok (K.Snapshot.of_string source))
let request ?(resource="configmaps") verb namespace name : Ir.request =
  {principal=Ir.Authenticated "app";action=verb;resource="";context=[];
   source=0l;host="";scheme="";sni="";
   object_request=Some {namespace;resource_kind=resource;name}}
let request_json (r:Ir.request) =
  let object_ = Option.get r.object_request in
  K.Input.json (`A [`O ["id",`String "one";"username",`String "app";"groups",strings ["writers"];
    "verb",`String r.action;"apiGroup",`String "";"resourceRequest",`Bool true;"subresource",`String "";
    "namespace",`String object_.namespace;"resource",`String object_.resource_kind;"name",`String object_.name]])
let outcome = function
  | Report.Proved -> "proved" | Violated _ -> "violated" | Unknown _ -> "unknown"
  | Vacuous -> "vacuous" | Inconsistent _ -> "inconsistent"
let ce_request (ce:Report.counterexample) =
  let object_ = Option.get ce.object_request in
  request ~resource:object_.resource_kind ce.action object_.namespace object_.name
let verify label s source expected =
  let report = K.Verify.run s source in
  check (label ^ " outcome") (outcome report.result=expected);
  check (label ^ " profile") ((Option.get report.assurance).profile=K.Assurance.write_profile_id);
  check (label ^ " frozen contract") (report.frozen_spec=Some (K.Contract_spec.frozen_spec s));
  (match report.result with
   | Report.Violated ce ->
     let p = policy s source and r = ce_request ce in
     let clause = List.find (fun c -> Contract.name c=(Option.get report.clause).name)
       (K.Contract_spec.to_contract s).clauses in
     check (label ^ " independently checked witness") (Witness.clause p clause r);
     check (label ^ " provenance") (ce.granting_rules=K.Lower.granting_rules p r);
     check (label ^ " frozen groups") (ce.identity_groups=Some ["writers"])
   | _ -> ()); report
let compare label s before after expected =
  let comparison = K.Verify.compare_with_trace s ~before ~after in
  check (label ^ " outcome") (outcome comparison.report.result=expected);
  check (label ^ " candidate proved")
    ((Option.get comparison.candidate_report).result=Report.Proved);
  (match comparison.report.result with
   | Report.Violated ce ->
     check (label ^ " preservation clause") ((Option.get comparison.report.clause).kind=Report.Must_preserve);
     let r = ce_request ce in
     check (label ^ " concrete difference outside approved scope")
       (Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes s))
          (policy s before) (policy s after) r)
   | _ -> ()); comparison.report

let () =
  let s = spec (contract ()) in
  let legacy version = spec (contract ~version ~deny:(scope ~resource:"secrets" ()) ()) in
  let v1,v2 = legacy 1,legacy 2 in
  List.iter (fun s ->
    let canonical = K.Contract_spec.canonical s in
    check "canonical roundtrip" (K.Contract_spec.canonical (ok (K.Contract_spec.of_string canonical))=canonical)) [v1;v2;s];
  check "version 3 identity" (K.Contract_spec.version s=3 && (K.Contract_spec.frozen_spec s).schema_version=3);
  check "profile version 3 identity" (K.Assurance.id_for_version 3=K.Assurance.write_profile_id);
  List.iter (fun verb -> List.iter (fun (ns,valid_ns) -> List.iter (fun (name,valid_name) ->
      let r = request verb ns name in
      let expected = valid_ns && valid_name in
      check "named writes have exact nonempty domain" (Ir.matches (K.Lower.domain s) r=expected);
      check "concrete input validates named writes" (Result.is_ok (K.Evaluate.requests s (request_json r))=expected);
      List.iter (fun old ->
        check "legacy domain excludes writes" (not (Ir.matches (K.Lower.domain old) r));
        check "legacy concrete evaluator rejects writes" (Result.is_error (K.Evaluate.requests old (request_json r)))) [v1;v2])
      ["settings",true;"a.b",true;String.make 253 'a',true;"",false;"*",false;"Bad",false;
       "a/b",false;"a\000b",false;String.make 254 'a',false])
      ["team",true;String.make 63 'a',true;"",false;"Bad",false;"a.b",false;String.make 64 'a',false]) writes;
  List.iter (fun verb -> check "unsupported verbs rejected"
    (Result.is_error (K.Evaluate.requests s (request_json (request verb "team" "settings")))))
    ["create";"deletecollection";"unsafe-delete-ignore-read-errors";"bind";"escalate";"*"];
  List.iter (fun resource -> check "unsupported resources rejected"
    (Result.is_error (K.Evaluate.requests s (request_json (request ~resource "patch" "team" "settings")))))
    ["pods";"secrets/status"];
  List.iter (fun verb -> List.iter (fun old ->
    check "old contracts reject write clauses" (Result.is_error (K.Contract_spec.of_string
      (K.Input.json (contract ~version:old ~allow:(scope ~verb ()) ~deny:(scope ~resource:"secrets" ()) ()))));
    check "old contracts reject write change scope" (Result.is_error (K.Contract_spec.of_string
      (K.Input.json (contract ~version:old ~deny:(scope ~resource:"secrets" ()) ~changes:[scope ~verb ()] ()))))) [2]) writes;
  List.iter (fun verb -> List.iter (fun changed ->
    check "write contract rejects malformed scope" (Result.is_error (K.Contract_spec.of_string (K.Input.json changed))))
    [contract ~allow:(scope ~verb ~ns:`Null ()) ();
     contract ~changes:[scope ~verb ~ns:`Null ()] ();
     contract ~allow:(scope ~verb ~ns:(`String "") ()) ();
     contract ~allow:(scope ~verb ~names:(strings [""]) ()) ();
     contract ~allow:(scope ~verb ~names:(strings ["*"]) ()) ();
     contract ~allow:(scope ~verb ~names:(strings []) ()) ();
     contract ~allow:(scope ~verb ~names:(strings ["settings";"settings"]) ()) ()]) writes;
  List.iter (fun verb -> check "unsupported contract verb rejected"
    (Result.is_error (K.Contract_spec.of_string (K.Input.json (contract ~allow:(scope ~verb ()) ())))))
    ["create";"deletecollection";"unsafe-delete-ignore-read-errors"];
  List.iter (fun cluster -> List.iter (fun group -> List.iter (fun names ->
    let p = policy s (snapshot ~cluster ~group [rule ~verbs:writes ~names "configmaps"]) in
    List.iter (fun verb -> List.iter (fun ns -> List.iter (fun name ->
      let expected = (cluster || ns="team") && (names=[] || List.mem name names) in
      let r = request verb ns name in
      check "write literal names/binding/subject union" (Ir.possibly_allows p r=expected);
      check "exact definite write allowance" (Ir.definitely_allows p r=expected))
      ["settings";"other"]) ["team";"other"]) writes)
      [[];["settings"];[""];["*"];["";"settings"]]) [false;true]) [false;true];
  List.iter (fun permitted ->
    let p = policy s (snapshot [rule ~verbs:[permitted] "configmaps"]) in
    List.iter (fun verb -> check "write/read verbs stay independent"
      (Ir.possibly_allows p (request verb "team" "settings")=(permitted="*" || permitted=verb)))
      (reads @ writes)) (reads @ writes @ ["*";"create";"deletecollection"]);
  let wildcard = policy s (snapshot ~cluster:true [rule ~verbs:["*"] ~groups:["*"] "*"]) in
  List.iter (fun verb -> check "wildcards include named Secret writes"
    (Ir.possibly_allows wildcard (request ~resource:"secrets" verb "other" "key"))) writes;
  List.iter (fun verb ->
    let required = scope ~verb ~names:(strings ["settings"]) () in
    let s = spec (contract ~allow:required ~deny:(scope ~verb ~resource:"secrets" ()) ()) in
    let grant = rule ~verbs:[verb] ~names:["settings"] "configmaps" in
    ignore (verify (verb ^ " named required write") s (snapshot [grant]) "proved");
    List.iter (fun names -> ignore (verify (verb ^ " nonmatching name loses required write") s
      (snapshot [rule ~verbs:[verb] ~names "configmaps"]) "violated")) [[""];["*"];["other"]];
    let leaked = verify (verb ^ " forbidden Secret write") s
      (snapshot [grant;rule ~verbs:[verb] ~names:["signing-key"] "secrets"]) "violated" in
    let ce = match leaked.result with Report.Violated ce -> ce | _ -> assert false in
    check "named forbidden write lifted precisely"
      (ce.action=verb && (Option.get ce.object_request).name="signing-key");
    ignore (verify (verb ^ " all-name requirement not met by one name")
      (spec (contract ~allow:(scope ~verb ()) ~deny:(scope ~verb ~resource:"secrets" ()) ()))
      (snapshot [grant]) "violated");
    ignore (verify (verb ^ " overlapping write intent")
      (spec (contract ~allow:required ~deny:(scope ~verb ()) ()))
      (snapshot [grant]) "inconsistent")) writes;
  ignore (verify "different verbs do not contradict"
    (spec (contract ~allow:(scope ~verb:"update" ()) ~deny:(scope ~verb:"delete" ()) ()))
    (snapshot [rule ~verbs:["update"] "configmaps"]) "proved");
  let read_only = snapshot [rule "configmaps"] in
  List.iter (fun verb ->
    let before = snapshot [rule "configmaps";rule ~verbs:[verb] "configmaps"] in
    ignore (compare (verb ^ " v1 preservation unchanged") v1 before read_only "proved");
    ignore (compare (verb ^ " v2 preservation unchanged") v2 before read_only "proved");
    ignore (compare (verb ^ " v3 preserves unmentioned writes") s before read_only "violated");
    ignore (compare (verb ^ " explicit change approved")
      (spec (contract ~changes:[scope ~verb ()] ())) before read_only "proved");
    ignore (compare (verb ^ " get change scope cannot approve write")
      (spec (contract ~changes:[scope ()] ())) before read_only "violated");
    ignore (compare (verb ^ " name scope cannot approve all names")
      (spec (contract ~changes:[scope ~verb ~names:(strings ["settings"]) ()] ())) before read_only "violated")) writes;
  let read_reduction = snapshot [rule ~verbs:["get"] "configmaps"] in
  ignore (compare "v3 preserves unmentioned collection reads"
    (spec (contract ~changes:(List.map (fun verb -> scope ~verb ()) writes) ())) read_only read_reduction "violated");
  let before = snapshot [rule "configmaps";rule ~verbs:["update";"patch"] "secrets"] in
  let repaired = snapshot [rule "configmaps";rule ~verbs:["patch"] "secrets"] in
  ignore (compare "authorized update removal preserves patch"
    (spec (contract ~changes:[scope ~verb:"update" ~resource:"secrets" ()] ())) before repaired "proved");
  ignore (compare "authorized update removal cannot hide patch removal"
    (spec (contract ~changes:[scope ~verb:"update" ~resource:"secrets" ()] ())) before read_only "violated");
  ignore (verify "unsupported snapshot retains v3 profile" s "{}" "unknown");
  Printf.printf "RBAC named write access: %d checks passed\n" !checks
