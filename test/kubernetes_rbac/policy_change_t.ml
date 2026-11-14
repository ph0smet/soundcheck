module K = Soundcheck_kubernetes_rbac
module C = K.Change_spec
module P = K.Policy_change
module S = K.Snapshot

(* Authorization-only tests: never invoke Policy_change.run, Verify or Z3.
   Native expectations follow Kubernetes v1.34.0 escalation_check.go and the
   four pkg/registry/rbac/*/policybased/storage.go wrappers. Their independent
   native conformance harness checks the complete target behavior separately. *)
let checks = ref 0
let check name yes = incr checks; if not yes then failwith ("policy change: " ^ name)
let ok = function Ok value -> value | Error reason -> failwith reason
let str x = `String x
let strings xs = `A (List.map str xs)
let json = K.Input.json
let fields = function `O fields -> fields | _ -> failwith "object required"
let field key value = List.assoc key (fields value)
let replace key value obj = `O (List.map (fun (k,v) -> k,if k=key then value else v) (fields obj))
let add key value obj = `O (fields obj @ [key,value])
let remove key obj = `O (List.filter (fun (k,_) -> k<>key) (fields obj))
let contains text fragment =
  let rec at i = i + String.length fragment <= String.length text &&
    (String.sub text i (String.length fragment)=fragment || at (i+1)) in at 0
let error name fragment = function
  | Error reason -> check name (contains reason fragment)
  | Ok _ -> check name false
let rr ?(verbs=["get"]) ?(group="") ?(resources=["pods"]) ?(names=[]) () =
  `O ["verbs",strings verbs;"apiGroups",strings [group];"resources",strings resources;"resourceNames",strings names]
let nr ?(verbs=["get"]) urls = `O ["verbs",strings verbs;"nonResourceURLs",strings urls]
let subject kind name = `O ["kind",str kind;"apiGroup",str K.Input.group;"name",str name]
let sa ?namespace name = `O (["kind",str "ServiceAccount";"name",str name] @
  match namespace with None -> [] | Some ns -> ["namespace",str ns])
let namespaced = function "Role" | "RoleBinding" -> true | _ -> false
let resource = function "Role" -> "roles" | "ClusterRole" -> "clusterroles"
  | "RoleBinding" -> "rolebindings" | "ClusterRoleBinding" -> "clusterrolebindings" | _ -> assert false
let metadata ?(namespace="") name = `O ["name",str name;"namespace",str namespace]
let role ?(namespace="") kind name rules = `O ["apiVersion",str K.Input.api_version;
  "kind",str kind;"metadata",metadata ~namespace name;"rules",`A rules]
let binding ?(namespace="") kind name ref_kind ref_name subjects =
  `O ["apiVersion",str K.Input.api_version;"kind",str kind;"metadata",metadata ~namespace name;
      "subjects",`A subjects;"roleRef",`O ["apiGroup",str K.Input.group;"kind",str ref_kind;"name",str ref_name]]
let source items = json (`O ["apiVersion",str "v1";"kind",str "List";"items",`A items])
let requirements ?(version=1) ?(actor="alice") ?(groups=[]) () =
  let scope resource names = ["subject",str actor;"namespace",str "apps";"resource",str resource;"names",strings names]
    @ (if version>=8 then ["operation",str "get"] else if version>=2 then ["verb",str "get"] else [])
    @ (if version>=5 then ["api_group",str ""] else [])
    @ (if version>=7 then ["subresource",str ""] else [])
    @ (if version>=9 then ["request_kind",str "resource"] else []) in
  `O (["schema_version",`Number (string_of_int version);"kind",str "kubernetes-rbac-access";
    "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
      "identities",`A [`O ["username",str actor;"groups",strings groups];
                       `O ["username",str "observer";"groups",`A []]]];
    "clauses",`A [`O (["name",str "read-config";"kind",str "must_allow"] @ scope "configmaps" ["app"]);
                  `O (["name",str "keep-secret-private";"kind",str "must_not_grant"] @ scope "secrets" ["db"])];
    "change_scope",`A [`O (scope "secrets" ["db"])]] @
    if version>=9 then ["custom_resources",`A []] else [])
let contract ?(version=1) ?(actor="alice") ?(groups=[]) ?namespace ?(name="target") kind operation =
  let namespace = match namespace with Some ns -> ns | None -> if namespaced kind then "apps" else "" in
  `O ["schema_version",`Number "1";"kind",str C.kind;"actor",str actor;"operation",str operation;
      "target",`O ["kind",str kind;"namespace",(if namespace="" then `Null else str namespace);"name",str name];
      "requirements",requirements ~version ~actor ~groups ()]
let spec ?version ?actor ?groups ?namespace ?name kind operation =
  contract ?version ?actor ?groups ?namespace ?name kind operation |> json |> C.of_string |> ok
let authorize spec before after = P.authorize spec ~before:(source before) ~after:(source after)
let initial ?(names=[]) kind operation =
  rr ~group:K.Input.group ~verbs:[if operation="create" then "create" else "update"]
    ~resources:[resource kind] ~names ()
let special ?(names=[]) verb resources = rr ~group:K.Input.group ~verbs:[verb] ~resources:[resources] ~names ()
let authority ?namespace ?(subjects=[subject "User" "alice"]) rules =
  [role "ClusterRole" "actor-policy" rules;
   match namespace with
   | None -> binding "ClusterRoleBinding" "actor-grant" "ClusterRole" "actor-policy" subjects
   | Some namespace -> binding ~namespace "RoleBinding" "actor-grant" "ClusterRole" "actor-policy" subjects]
let fixture ?(namespace="apps") ?ref_kind ?(old_rules=[]) ?(proposed_rules=[rr ()])
    ?(old_subjects=[subject "User" "bob"]) ?(new_subjects=[subject "User" "carol"])
    kind operation authority =
  let ns = if namespaced kind then namespace else "" in
  let reference_kind = match ref_kind with Some k -> k | None -> if kind="RoleBinding" then "Role" else "ClusterRole" in
  let reference_namespace = if reference_kind="Role" then ns else "" in
  let refs,old_target,new_target =
    if kind="Role" || kind="ClusterRole" then [],role ~namespace:ns kind "target" old_rules,role ~namespace:ns kind "target" proposed_rules
    else [role ~namespace:reference_namespace reference_kind "referenced" proposed_rules],
      binding ~namespace:ns kind "target" reference_kind "referenced" old_subjects,
      binding ~namespace:ns kind "target" reference_kind "referenced" new_subjects in
  let base = authority @ refs in
  base @ (if operation="create" then [] else [old_target]),base @ [new_target]
let auth ?namespace ?ref_kind ?old_rules ?proposed_rules ?old_subjects ?new_subjects
    ?version ?actor ?groups kind operation authority =
  let before,after = fixture ?namespace ?ref_kind ?old_rules ?proposed_rules ?old_subjects ?new_subjects kind operation authority in
  authorize (spec ?version ?actor ?groups ?namespace kind operation) before after |> ok
let target_last f xs = List.mapi (fun i value -> if i=List.length xs-1 then f value else value) xs
let with_metadata key value object_ = replace "metadata" (add key value (field "metadata" object_)) object_
let rec reverse_maps = function
  | `O fields -> `O (List.rev_map (fun (key,value) -> key,reverse_maps value) fields)
  | `A values -> `A (List.map reverse_maps values)
  | value -> value

let () =
  for version=1 to 10 do
    let source=contract ~version ~groups:["z";"a"] "Role" "create" in
    let value=ok (C.of_string (json source)) in
    check "nested schema retained" (K.Contract_spec.version (C.requirements value)=version);
    check "nested canonical identity retained" (K.Contract_spec.canonical (C.requirements value)=
      K.Contract_spec.canonical (ok (K.Contract_spec.of_string (json (field "requirements" source)))));
    check "contract round trip" (C.canonical (ok (C.of_string (C.canonical value)))=C.canonical value);
    check "trusted groups retained in canonical order" ((C.actor value).groups=["a";"z"]);
    check "review describes fixed actor and original authority"
      (contains (C.review value) "alice" && contains (C.review value) "original snapshot")
  done;
  let normal=contract "Role" "create" in
  List.iter (fun (name,value) -> error name "" (C.of_string (json value))) [
    "unknown contract field",add "allow_mutable_actor" (`Bool true) normal;
    "duplicate contract field",add "actor" (str "alice") normal;
    "missing actor",remove "actor" normal;
    "actor must be string",replace "actor" (`O ["username",str "alice"]) normal;
    "actor not trusted",replace "actor" (str "mallory") normal;
    "actor case is exact",replace "actor" (str "Alice") normal;
    "wrong contract kind",replace "kind" (str "kubernetes-rbac-access") normal;
    "unknown version",replace "schema_version" (`Number "2") normal;
    "rounded version",replace "schema_version" (`Number "1.0") normal;
    "string version",replace "schema_version" (str "1") normal;
    "missing requirements",remove "requirements" normal;
    "unknown nested field",replace "requirements" (add "inferred_groups" (`Bool true) (field "requirements" normal)) normal;
    "unknown target field",replace "target" (add "resource" (str "roles") (field "target" normal)) normal;
    "duplicate target field",replace "target" (add "name" (str "target") (field "target" normal)) normal;
    "unsupported target kind",replace "target" (replace "kind" (str "Secret") (field "target" normal)) normal;
    "namespaced target needs namespace",replace "target" (replace "namespace" `Null (field "target" normal)) normal;
    "namespace is exact DNS label",replace "target" (replace "namespace" (str "*") (field "target" normal)) normal];
  List.iter (fun operation -> error "unsupported operation" "expected create or update-existing"
    (C.of_string (json (replace "operation" (str operation) normal))))
    ["update";"patch";"apply";"delete";"create-on-update";""];
  List.iter (fun name -> error "invalid exact target name" "" (C.of_string (json
    (replace "target" (replace "name" (str name) (field "target" normal)) normal)))) ["";"..";"a/b";"a%b"];
  error "cluster target must use null namespace" "null" (C.of_string (json (contract ~namespace:"apps" "ClusterRole" "create")));
  error "masters actor rejected" "system:masters" (C.of_string (json (contract ~groups:["system:masters"] "Role" "create")));
  check "masters username alone does not grant bypass" (Result.is_ok (C.of_string (json (contract ~actor:"system:masters" "Role" "create"))));
  check "nearby group name is not bypass" (Result.is_ok (C.of_string (json (contract ~groups:["system:masters-extra"] "Role" "create"))));
  let incomplete = replace "context" (replace "snapshot_complete" (`Bool false) (field "context" (field "requirements" normal))) (field "requirements" normal) in
  error "nested completeness assertion required" "complete" (C.of_string (json (replace "requirements" incomplete normal)));

  List.iter (fun kind -> List.iter (fun operation ->
    let ns=if namespaced kind then "apps" else "" in
    let explicit=if kind="Role" || kind="ClusterRole" then special "escalate" (resource kind)
      else special ~names:["referenced"] "bind" (if kind="RoleBinding" then "roles" else "clusterroles") in
    let a=auth kind operation (authority [initial kind operation;explicit]) in
    check (kind ^ " " ^ operation ^ " explicit authority") (a.allowed && a.coverage=None);
    check "initial verb" (a.initial.attributes.verb=(if operation="create" then "create" else "update"));
    check "initial target resource" (a.initial.attributes.resource=resource kind);
    check "initial namespace" (a.initial.attributes.namespace=ns);
    check "initial create empty / update named" (a.initial.attributes.name=(if operation="create" then "" else "target"));
    let special_check=Option.get a.special in
    check "special namespace" (special_check.attributes.namespace=ns);
    check "special name source" (special_check.attributes.name=
      if kind="Role" || kind="ClusterRole" then (if operation="create" then "" else "target") else "referenced");
    check "special verb" (special_check.attributes.verb=(if kind="Role" || kind="ClusterRole" then "escalate" else "bind"));
    let implicit=auth kind operation (authority [initial kind operation;rr ()]) in
    check "full baseline policy coverage fallback" (implicit.allowed && (Option.get implicit.coverage).covered);
    let no_initial=auth kind operation (authority [explicit;rr ()]) in
    check "initial request is required before either shortcut"
      (not no_initial.allowed && no_initial.special=None && no_initial.coverage=None);
    let no_special=auth kind operation (authority [initial kind operation]) in
    check "missing explicit and implicit authority rejected"
      (not no_special.allowed && no_special.special<>None && not (Option.get no_special.coverage).covered);
    let named_initial=auth kind operation (authority [initial ~names:["target"] kind operation;explicit]) in
    check "create does not use request-body name for initial authorization" (named_initial.allowed=(operation="update-existing"));
    let wrong_initial=auth kind operation (authority [initial ~names:["other"] kind operation;explicit]) in
    check "wrong initial name fails" (not wrong_initial.allowed && wrong_initial.special=None)) ["create";"update-existing"])
    ["Role";"ClusterRole";"RoleBinding";"ClusterRoleBinding"];

  List.iter (fun kind -> List.iter (fun operation ->
    let a=auth kind operation (authority [initial kind operation;special ~names:["target"] "escalate" (resource kind)]) in
    check "escalate create uses URL name, not body name" (a.allowed=(operation="update-existing"));
    let wrong=auth kind operation (authority [initial kind operation;special ~names:["other"] "escalate" (resource kind)]) in
    check "escalate wrong name cannot bypass coverage" (not wrong.allowed && wrong.coverage<>None)) ["create";"update-existing"])
    ["Role";"ClusterRole"];
  List.iter (fun kind -> List.iter (fun operation ->
    let ref_resource=if kind="RoleBinding" then "roles" else "clusterroles" in
    let a=auth kind operation (authority [initial kind operation;special ~names:["target"] "bind" ref_resource]) in
    check "bind is checked against roleRef name, not binding name" (not a.allowed && a.coverage<>None)) ["create";"update-existing"])
    ["RoleBinding";"ClusterRoleBinding"];
  let delegated=authority ~namespace:"apps" [initial "RoleBinding" "create";
    special ~names:["referenced"] "bind" "clusterroles"] in
  let a=auth ~ref_kind:"ClusterRole" "RoleBinding" "create" delegated in
  check "namespaced delegation can bind a ClusterRole" a.allowed;
  check "ClusterRole bind retains binding namespace" ((Option.get a.special).attributes.namespace="apps");
  check "ClusterRole bind targets roleRef resource" ((Option.get a.special).attributes.resource="clusterroles");
  let elsewhere=auth ~namespace:"other" ~ref_kind:"ClusterRole" "RoleBinding" "create" delegated in
  check "namespaced delegation cannot move to another namespace" (not elsewhere.allowed);
  let global=auth "ClusterRole" "create" (authority ~namespace:"apps" [initial "ClusterRole" "create";special "escalate" "clusterroles"]) in
  check "RoleBinding cannot grant cluster-scope initial write" (not global.allowed);

  let group_authority=authority ~subjects:[subject "Group" "builders"] [initial "Role" "create";rr ()] in
  check "explicit trusted group authorizes" (auth ~groups:["builders"] "Role" "create" group_authority).allowed;
  check "group membership is not inferred" (not (auth "Role" "create" group_authority).allowed);
  check "group matching is exact" (not (auth ~groups:["Builders"] "Role" "create" group_authority).allowed);
  let sa_authority=authority ~namespace:"apps" ~subjects:[sa "worker"] [initial "Role" "create";rr ()] in
  check "service-account default namespace uses binding namespace"
    (auth ~actor:"system:serviceaccount:apps:worker" "Role" "create" sa_authority).allowed;
  check "service-account other namespace is distinct"
    (not (auth ~actor:"system:serviceaccount:other:worker" "Role" "create" sa_authority).allowed);

  let unknown=rr ~group:"foreign.example.net" ~verbs:["frob"] ~resources:["unknown/a/b"] ~names:["*"] () in
  let uncovered=auth ~version:1 ~proposed_rules:[rr ();unknown] "Role" "create" (authority [initial "Role" "create";rr ()]) in
  check "schema1 does not discard unknown-policy obligations" (not uncovered.allowed);
  let missing=(Option.get uncovered.coverage).missing in
  check "foreign whole-policy atom retained"
    (List.map (fun (m:K.Policy_coverage.missing) -> m.proposed_rule_index,m.atom_index) missing=[1,0]);
  check "foreign atom bytes retained" (match (List.hd missing).rule with
    | S.Resource r -> r.api_groups=["foreign.example.net"] && r.resources=["unknown/a/b"] && r.verbs=["frob"] && r.resource_names=["*"]
    | _ -> false);
  let url=auth ~ref_kind:"ClusterRole" ~proposed_rules:[nr ["/unknown/**"]] "RoleBinding" "create"
    (authority [initial "RoleBinding" "create"]) in
  check "binding fallback retains nonresource URL policy" (not url.allowed && (Option.get url.coverage).atom_count=1);
  let covered_url=auth ~ref_kind:"ClusterRole" ~proposed_rules:[nr ["/unknown/**"]] "RoleBinding" "create"
    (authority [initial "RoleBinding" "create";nr ["/unknown/*"]]) in
  check "binding fallback permits native URL prefix coverage" covered_url.allowed;
  let scoped_unknown=auth ~ref_kind:"ClusterRole" ~proposed_rules:[unknown] "RoleBinding" "create"
    (authority ~namespace:"apps" [initial "RoleBinding" "create";unknown]) in
  check "RulesFor coverage does not project namespace-bound rules by resource kind" scoped_unknown.allowed;
  let retained=auth ~old_rules:[unknown] ~proposed_rules:[unknown;rr ()] "Role" "update-existing"
    (authority [initial "Role" "update-existing";rr ()]) in
  check "full proposed policy checked, including unchanged unheld permissions" (not retained.allowed);
  let emptied=auth ~old_rules:[unknown] ~proposed_rules:[] "Role" "update-existing"
    (authority [initial "Role" "update-existing"]) in
  check "role coverage applies to proposed rules rather than removed old permissions"
    (emptied.allowed && (Option.get emptied.coverage).atom_count=0);
  let empty_binding=auth ~new_subjects:[] "RoleBinding" "create" (authority [initial "RoleBinding" "create"]) in
  check "empty binding subjects do not bypass reference coverage" (not empty_binding.allowed);
  let removed_binding=auth ~new_subjects:[] "RoleBinding" "update-existing" (authority [initial "RoleBinding" "update-existing"]) in
  check "removing binding subjects still requires bind or referenced-policy coverage" (not removed_binding.allowed);
  let rendered=K.Input.parse (P.authorization_json uncovered) in
  check "authorization diagnostics distinguish native computation" (field "method" rendered=str "deterministic-native-rbac-policy-coverage");
  check "authorization report has no fabricated request counterexample" (not (List.mem_assoc "counterexample" (fields rendered)));
  check "authorization report retains atomic coverage" (field "covered" (field "coverage" rendered)=`Bool false);

  let own_initial=initial "Role" "update-existing" in
  let self_before=[role ~namespace:"apps" "Role" "target" [own_initial;rr ()];
    binding ~namespace:"apps" "RoleBinding" "self" "Role" "target" [subject "User" "alice"]] in
  let self_after=List.map (fun v -> if field "kind" v=str "Role" then replace "rules" (`A [own_initial;rr ();special "escalate" "roles";unknown]) v else v) self_before in
  let self=ok (authorize (spec "Role" "update-existing") self_before self_after) in
  check "newly added escalate cannot authorize a self-edit" (not self.allowed && self.initial.granting_rules<>[] && (Option.get self.special).granting_rules=[]);
  let removed=List.map (fun v -> if field "kind" v=str "Role" then replace "rules" (`A []) v else v) self_before in
  check "removing one's own authority uses original grants" (ok (authorize (spec "Role" "update-existing") self_before removed)).allowed;
  List.iter (fun kind ->
    let before,after=fixture ~old_subjects:[subject "User" "bob"] ~new_subjects:[subject "User" "bob";subject "User" "alice"]
      ~proposed_rules:[initial kind "update-existing";unknown] kind "update-existing" (authority [initial kind "update-existing"]) in
    let a=ok (authorize (spec kind "update-existing") before after) in
    check "new self-binding grants cannot authorize themselves" (not a.allowed && a.coverage<>None)) ["RoleBinding";"ClusterRoleBinding"];

  let admin=authority [rr ~group:K.Input.group ~verbs:["*"] ~resources:["*"] ()] in
  let before,after=fixture "Role" "update-existing" admin in
  let operation=spec "Role" "update-existing" in
  error "no-op update rejected" "no-op" (authorize operation before before);
  error "metadata-only update rejected" "metadata-only"
    (authorize operation before (target_last (with_metadata "labels" (`O ["reviewed",str "true"])) before));
  check "metadata can accompany typed rule change"
    (ok (authorize operation before (target_last (with_metadata "annotations" (`O ["reason",str "reviewed"])) after))).allowed;
  check "object order and map-key order are irrelevant"
    (ok (authorize operation before (List.rev_map reverse_maps after))).allowed;
  error "unrelated object added" "only the frozen target" (authorize operation before (after @ [role "ClusterRole" "extra" []]));
  error "unrelated object removed" "unresolved roleRef" (authorize operation before (List.tl after));
  let detached=role "ClusterRole" "detached" [] in
  error "unbound unrelated object removal rejected" "only the frozen target"
    (authorize operation (before @ [detached]) after);
  error "unrelated metadata representation change rejected" "only the frozen target"
    (authorize operation before (List.mapi (fun i v -> if i=0 then with_metadata "labels" (`O []) v else v) after));
  error "target missing rejected" "candidate must contain" (authorize operation before admin);
  error "target renamed rejected" "candidate must contain"
    (authorize operation before (target_last (fun v -> replace "metadata" (replace "name" (str "other") (field "metadata" v)) v) after));
  error "create requires target absent" "absent" (authorize (spec "Role" "create") before after);
  let empty_before,new_after=fixture "Role" "create" admin in
  error "update-existing cannot create" "requires an original target" (authorize operation empty_before new_after);
  error "duplicate identities are rejected" "duplicate RBAC" (authorize operation before (after @ [List.hd after]));
  error "original malformed inventory cannot be repaired inside authorization" "duplicate RBAC"
    (authorize operation (before @ [List.hd before]) after);
  error "unsupported metadata rejected" "unsupported field"
    (authorize operation before (target_last (with_metadata "finalizers" (`A [])) after));
  let two_rules=admin @ [role "ClusterRole" "ordered" [rr ();unknown]] in
  let b,a=fixture "Role" "update-existing" two_rules in
  let reordered=List.map (fun v -> if field "name" (field "metadata" v)=str "ordered" then replace "rules" (`A [unknown;rr ()]) v else v) a in
  error "unrelated rule order remains frozen" "only the frozen target" (authorize operation b reordered);
  let b,a=fixture ~old_rules:[rr ~verbs:["get";"list"] ()] ~proposed_rules:[rr ~verbs:["list";"get"] ()] "Role" "update-existing" admin in
  check "target rule array order is a native typed change" (ok (authorize operation b a)).allowed;
  let b,a=fixture ~old_rules:[rr ()] ~proposed_rules:[rr ();rr ()] "Role" "update-existing" admin in
  check "target rule duplicates are a native typed change" (ok (authorize operation b a)).allowed;
  let b,a=fixture ~old_subjects:[subject "User" "bob";subject "User" "carol"]
    ~new_subjects:[subject "User" "carol";subject "User" "bob"] "RoleBinding" "update-existing" admin in
  check "target subject order is retained for no-op detection" (ok (authorize (spec "RoleBinding" "update-existing") b a)).allowed;

  List.iter (fun kind ->
    let b,a=fixture kind "update-existing" admin in
    let ns=if kind="RoleBinding" then "apps" else "" in
    let ref_kind=if kind="RoleBinding" then "Role" else "ClusterRole" in
    let extra=role ~namespace:ns ref_kind "other-reference" [rr ()] in
    let b=b @ [extra] and a=target_last (fun v -> replace "roleRef" (replace "name" (str "other-reference") (field "roleRef" v)) v) a @ [extra] in
    error "binding roleRef immutable even with explicit bind authority" "roleRef is immutable"
      (authorize (spec kind "update-existing") b a)) ["RoleBinding";"ClusterRoleBinding"];
  let b,a=fixture "RoleBinding" "update-existing" admin in
  let alternate=role "ClusterRole" "referenced" [rr ()] in
  let changed_kind=target_last (fun v -> replace "roleRef"
      (replace "kind" (str "ClusterRole") (field "roleRef" v)) v) a in
  error "roleRef kind is immutable even when both roles exist" "roleRef is immutable"
    (authorize (spec "RoleBinding" "update-existing") (b @ [alternate]) (changed_kind @ [alternate]));

  let aggregate value = add "aggregationRule" (`O ["clusterRoleSelectors",`A [`O ["matchLabels",`O ["aggregate",str "yes"]]]]) value in
  let contributor=with_metadata "labels" (`O ["aggregate",str "yes"]) (role "ClusterRole" "contributor" []) in
  let b,a=fixture ~proposed_rules:[] "ClusterRole" "create" (admin @ [contributor]) in
  error "new aggregate target rejected" "aggregate ClusterRole targets"
    (authorize (spec "ClusterRole" "create") b (target_last aggregate a));
  let b,a=fixture ~old_rules:[] "ClusterRole" "update-existing" (admin @ [contributor]) in
  error "original aggregate target rejected even when selector removed" "aggregate ClusterRole targets"
    (authorize (spec "ClusterRole" "update-existing") (target_last aggregate b) a);
  let unrelated_aggregate=aggregate (role "ClusterRole" "unrelated-aggregate" []) in
  let b,a=fixture "Role" "update-existing" (admin @ [contributor;unrelated_aggregate]) in
  check "unchanged resolved non-target aggregate remains supported" (ok (authorize operation b a)).allowed;
  let inconsistent=replace "rules" (`A [rr ()]) unrelated_aggregate in
  error "unrelated stale aggregate invalidates whole snapshot" "stored rules"
    (authorize operation b (List.map (fun v -> if field "name" (field "metadata" v)=str "unrelated-aggregate" then inconsistent else v) a));
  Printf.printf "policy change authorization: %d checks passed (no solver)\n" !checks
