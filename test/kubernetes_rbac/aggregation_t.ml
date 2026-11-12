module K = Soundcheck_kubernetes_rbac
open K.Input

let checks = ref 0
let check label condition = incr checks; if not condition then failwith ("aggregation: " ^ label)
let ok = function Ok value -> value | Error reason -> failwith reason
let fields = function `O fields -> fields | _ -> failwith "object expected"
let field name value = List.assoc name (fields value)
let array = function `A values -> values | _ -> failwith "array expected"
let set name value obj = `O ((name,value)::List.remove_assoc name (fields obj))
let remove name obj = `O (List.remove_assoc name (fields obj))
let strings values = `A (List.map (fun value -> `String value) values)
let rec normalize = function
  | `O fields -> `O (List.map (fun (k,v) -> k,normalize v) fields |> List.sort compare)
  | `A values -> `A (List.map normalize values)
  | value -> value
let snapshot items = `O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items]
let role ?(kind="ClusterRole") ?(labels=[]) ?aggregation name rules =
  `O (["apiVersion",`String api_version;"kind",`String kind;
       "metadata",`O (["name",`String name;"labels",`O (List.map (fun (k,v) -> k,`String v) labels)]
         @ if kind="Role" then ["namespace",`String "apps"] else []);
       "rules",`A rules]
      @ match aggregation with None -> [] | Some value -> ["aggregationRule",value])
let selector labels = `O ["matchLabels",`O (List.map (fun (k,v) -> k,`String v) labels)]
let expression ?(values=[]) key operator = `O ["key",`String key;"operator",`String operator;"values",strings values]
let expressions values = `O ["matchExpressions",`A values]
let aggregate ?(labels=[]) name selectors rules =
  role ~labels ~aggregation:(`O ["clusterRoleSelectors",`A selectors]) name rules
let resource ?(verbs=["get"]) ?(groups=[""]) ?(resources=["configmaps"]) ?(names=[]) () =
  `O ["verbs",strings verbs;"apiGroups",strings groups;"resources",strings resources;"resourceNames",strings names]
let url urls = `O ["verbs",strings ["get"];"nonResourceURLs",strings urls]
let binding ?(namespace="apps") ?(kind="RoleBinding") ?(subject="alice") name target =
  `O ["apiVersion",`String api_version;"kind",`String kind;
      "metadata",`O (["name",`String name] @ if kind="RoleBinding" then ["namespace",`String namespace] else []);
      "subjects",`A [`O ["kind",`String "User";"apiGroup",`String group;"name",`String subject]];
      "roleRef",`O ["apiGroup",`String group;"kind",`String "ClusterRole";"name",`String target]]
let accepted label items =
  match K.Snapshot.of_string (json (snapshot items)) with
  | Ok value -> check label true; value
  | Error reason -> failwith (label ^ ": " ^ reason)
let rejected label items =
  match K.Snapshot.of_string (json (snapshot items)) with
  | Ok _ -> failwith (label ^ ": unsupported inventory accepted")
  | Error reason -> check (label ^ " has a diagnostic") (reason<>"")
let contract =
  let clause name kind resource = `O ["name",`String name;"kind",`String kind;
    "subject",`String "alice";"namespace",`String "apps";"resource",`String resource;
    "names",`Null;"verb",`String "get"] in
  json (`O ["schema_version",`Number "4";"kind",`String "kubernetes-rbac-access";
    "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
      "identities",`A [`O ["username",`String "alice";"groups",strings []];
                        `O ["username",`String "bob";"groups",strings []]]];
    "clauses",`A [clause "required" "must_allow" "configmaps";clause "forbidden" "must_not_grant" "secrets"];
    "change_scope",`A []])
let spec = lazy (K.Contract_spec.of_string contract |> ok)
let grants ?(username="alice") ?(namespace="apps") ?(resource="configmaps") ?(verb="get") items name =
  let spec = Lazy.force spec in
  let input = K.Snapshot.of_string (json (snapshot items)) |> ok in
  let policy = K.Lower.policy spec input in
  let requests = K.Evaluate.requests spec (json (`A [`O [
    "id",`String "probe";"username",`String username;"groups",strings [];"verb",`String verb;
    "apiGroup",`String "";"resource",`String resource;"namespace",`String namespace;"name",`String name;
    "subresource",`String "";"resourceRequest",`Bool true]])) |> ok in
  K.Evaluate.decisions policy requests |> array |> List.hd |> field "grants" |> array

let () =
  (* Literal truth tables follow Kubernetes label-selector semantics. NotIn
     also matches roles on which the key is absent. *)
  let rules = List.map (fun name -> name,resource ~names:[name] ()) ["alpha";"beta";"gamma";"empty"] in
  let lookup name = List.assoc name rules in
  let leaves = [
    role ~labels:["tenant","red";"tier","front"] "alpha" [lookup "alpha"];
    role ~labels:["tenant","blue";"tier","back"] "beta" [lookup "beta"];
    role ~labels:["tier","front"] "gamma" [lookup "gamma"];
    role ~labels:["tenant","";"tier","front"] "empty" [lookup "empty"]] in
  let cases = [
    "matchLabels",[selector ["tenant","red"]],["alpha"];
    "all matchLabels required",[selector ["tenant","blue";"tier","front"]],[];
    "In",[expressions [expression ~values:["blue";"red"] "tenant" "In"]],["alpha";"beta"];
    "NotIn includes absent",[expressions [expression ~values:["red"] "tenant" "NotIn"]],["beta";"gamma";"empty"];
    "Exists includes empty value",[expressions [expression "tenant" "Exists"]],["alpha";"beta";"empty"];
    "DoesNotExist",[expressions [expression "tenant" "DoesNotExist"]],["gamma"];
    "empty label is not absence",[selector ["tenant",""]],["empty"];
    "In empty value is not absence",[expressions [expression ~values:[""] "tenant" "In"]],["empty"];
    "NotIn empty includes absence",[expressions [expression ~values:[""] "tenant" "NotIn"]],["alpha";"beta";"gamma"];
    "expressions are AND",[expressions [expression ~values:["red";"blue"] "tenant" "In";
      expression ~values:["back"] "tier" "NotIn"]],["alpha"];
    "matchLabels and expressions are AND",[set "matchExpressions" (`A [expression "tenant" "DoesNotExist"])
      (selector ["tier","front"])],["gamma"];
    "selector list is OR",[selector ["tenant","red"];selector ["tenant","blue"]],["alpha";"beta"];
    "overlapping selectors union",[selector ["tenant","red"];expressions [expression ~values:["red"] "tenant" "In"]],["alpha"];
    "empty selector matches all",[`O []],["alpha";"beta";"gamma";"empty"];
    "null selector fields are empty",[`O ["matchLabels",`Null;"matchExpressions",`Null]],["alpha";"beta";"gamma";"empty"];
    "duplicate values are harmless",[expressions [expression ~values:["red";"red"] "tenant" "In"]],["alpha"];
    "unknown label selects no role",[selector ["not-present","yes"]],[]] in
  List.iter (fun (label,selectors,expected) ->
    let aggregate = aggregate "aggregate" selectors (List.map lookup expected) in
    let items = aggregate::leaves @ [binding "reader" "aggregate"] in
    ignore (accepted label items);
    List.iter (fun name -> check (label ^ " request " ^ name)
      ((grants items name<>[]) = List.mem name expected)) ["alpha";"beta";"gamma";"empty";"outside"];
    check (label ^ " RoleBinding remains local") (grants ~namespace:"elsewhere" items "alpha"=[]);
    check (label ^ " nonmatching identity receives no grant") (grants ~username:"bob" items "alpha"=[])) cases;

  let read = resource ~names:["settings"] () and secret = resource ~resources:["secrets"] () in
  let leaf = role ~labels:["part","leaf"] "leaf" [read] in
  let child = aggregate ~labels:["part","child"] "child" [selector ["part","leaf"]] [read] in
  let parent = aggregate "parent" [selector ["part","child"];selector ["part","leaf"]] [read] in
  let chain = [parent;child;leaf;binding "reader" "parent"] in
  ignore (accepted "nested acyclic aggregate" chain);
  ignore (accepted "object order has no effect" (List.rev chain));
  check "nested parent grants only its stored source rule" (grants chain "settings"=
    [`String "RoleBinding/apps/reader -> ClusterRole/parent/rules/0"]);
  check "no rule is inherited merely because its role exists" (grants (chain @ [role "unselected" [secret]]) "other"=[]);
  rejected "stale nested child cannot be hidden by correct parent" [parent;set "rules" (`A []) child;leaf];
  rejected "missing desired grant" [set "rules" (`A []) parent;child;leaf];
  rejected "extra stored grant" [set "rules" (`A [read;secret]) parent;child;leaf];
  rejected "unbound stale aggregate is still unsupported" (chain @ [aggregate "unbound" [selector ["part","leaf"]] []]);
  let self = aggregate ~labels:["self","yes"] "self" [selector ["self","yes"]] [] in
  ignore (accepted "self-selection is ignored" [self]);
  rejected "self-selection cannot justify stored seed permissions" [set "rules" (`A [read]) self];
  let cycle rules = [aggregate ~labels:["node","a"] "a" [selector ["node","b"]] rules;
    aggregate ~labels:["node","b"] "b" [selector ["node","a"]] rules] in
  rejected "empty unbound cycle" (cycle []);
  rejected "seeded stable cycle does not establish leaf-derived permissions" (cycle [read]);
  rejected "cycle hidden beside valid bound role" (chain @ cycle []);
  let local = role ~kind:"Role" ~labels:["part","leaf"] "local-only" [secret] in
  ignore (accepted "namespaced Roles are not ClusterRole contributors" [parent;child;leaf;local]);
  rejected "namespaced role cannot supply aggregate rules" [aggregate "wrong" [selector ["part","leaf"]] [secret];local];
  let annotated = role "annotated" [secret] |> fun item ->
    set "metadata" (set "annotations" (`O ["part",`String "leaf"]) (field "metadata" item)) item in
  ignore (accepted "annotations are not selector labels" [aggregate "empty" [selector ["part","leaf"]] [];annotated]);

  (* Consistency covers every policy field, including domains outside the
     current verification profile. *)
  let require_same label original stored =
    rejected label [role ~labels:["part","leaf"] "leaf" [original];
      aggregate "aggregate" [selector ["part","leaf"]] stored] in
  require_same "changed verb" read [set "verbs" (strings ["patch"]) read];
  require_same "changed API group" read [set "apiGroups" (strings ["other.example"]) read];
  require_same "changed resource kind" read [set "resources" (strings ["pods"]) read];
  require_same "changed authorization name" read [set "resourceNames" (strings ["other"]) read];
  require_same "omitted out-of-profile permission" (resource ~groups:["apps"] ~resources:["deployments"] ()) [];
  require_same "omitted nonresource permission" (url ["/version"]) [];
  require_same "changed nonresource URL" (url ["/version"]) [url ["/healthz"]];
  require_same "resource wildcard cannot be narrowed" (resource ~resources:["*"] ()) [resource ()];
  require_same "equivalent rule splitting is outside structural equality"
    (resource ~verbs:["get";"list"] ()) [resource ();resource ~verbs:["list"] ()];
  let many = resource ~verbs:["get";"patch";"get"] ~groups:["";"apps"]
    ~resources:["configmaps";"deployments"] ~names:["settings";"other"] () in
  let reordered = resource ~verbs:["patch";"get"] ~groups:["apps";""]
    ~resources:["deployments";"configmaps"] ~names:["other";"settings";"other"] () in
  ignore (accepted "membership order and duplicates do not alter rule equality"
    [role ~labels:["part","leaf"] "leaf" [many];aggregate "aggregate" [selector ["part","leaf"]] [reordered;reordered]]);
  let mixed_leaf = role ~labels:["part","leaf"] "leaf" [read;url ["/version";"/healthz"]] in
  let mixed = aggregate "aggregate" [selector ["part","leaf"]]
    [url ["/healthz";"/version";"/version"];read;read] in
  let mixed_items = [mixed;mixed_leaf;binding "reader" "aggregate"] in
  ignore (accepted "normalized rule set retains original rule slots" mixed_items);
  check "unchanged source rule indices including duplicates" (grants mixed_items "settings"=
    [`String "RoleBinding/apps/reader -> ClusterRole/aggregate/rules/1";
     `String "RoleBinding/apps/reader -> ClusterRole/aggregate/rules/2"]);
  check "URL rules do not acquire resource access" (grants ~resource:"secrets" mixed_items "settings"=[]);
  ignore (accepted "null and absent aggregation are nonaggregated" [role ~aggregation:`Null "plain" [read]]);

  let bad_aggregate label aggregation = rejected label [role ~aggregation "bad" []] in
  List.iter (fun value -> bad_aggregate "malformed aggregationRule" value)
    [`String "";`Bool false;`A [];`Number "1";`O [];`O ["clusterRoleSelectors",`Null];
     `O ["clusterRoleSelectors",`A []];`O ["clusterRoleSelectors",`String "all"]];
  List.iter (fun value -> bad_aggregate "malformed selector" (`O ["clusterRoleSelectors",`A [value]]))
    [`Null;`String "";`A [];`O ["unknown",`Null];`O ["matchLabels",`A []];
     `O ["matchLabels",`O ["bad/key/name",`String "x"]];
     `O ["matchLabels",`O ["valid",`String "bad value"]];
     `O ["matchLabels",`O ["valid",`Bool true]];`O ["matchExpressions",`O []]];
  let bad_expression label expr = bad_aggregate label (`O ["clusterRoleSelectors",`A [expressions [expr]]]) in
  List.iter (fun expr -> bad_expression "invalid selector expression" expr)
    [`Null;`O [];remove "key" (expression "x" "Exists");remove "operator" (expression "x" "Exists");
     expression "bad/key/name" "Exists";expression "x" "exists";expression "x" "Gt";
     expression "x" "In";expression "x" "NotIn";
     expression ~values:["x"] "x" "Exists";expression ~values:["x"] "x" "DoesNotExist";
     expression ~values:["bad value"] "x" "In";
     set "values" (`String "x") (expression "x" "In");
     set "values" (`A [`Null]) (expression "x" "In");
     set "extra" `Null (expression "x" "Exists")];
  bad_aggregate "unknown aggregation field" (`O ["clusterRoleSelectors",`A [`O []];"future",`Null]);
  bad_aggregate "duplicate selector field" (`O ["clusterRoleSelectors",`A [`O ["matchLabels",`O [];"matchLabels",`O []]]]);
  rejected "Role cannot carry aggregation even null" [role ~kind:"Role" ~aggregation:`Null "bad" []];
  rejected "malformed unselected role still fails closed" [self;role "bad" [resource () |> set "verbs" (`A [])]];
  let plain_roles n = List.init n (fun i -> role ("plain-" ^ string_of_int i) []) in
  ignore (accepted "nonaggregate inventories do not acquire aggregate-only limit" (plain_roles 513));
  ignore (accepted "512 ClusterRoles fit aggregate budget" (self::plain_roles 511));
  rejected "513 ClusterRoles exceed aggregate budget" (self::plain_roles 512);
  ignore (accepted "1024 empty selectors fit predicate budget"
    [aggregate "empty" (List.init 1024 (fun _ -> `O [])) []]);
  rejected "selector count participates in budget" [aggregate "empty" (List.init 1025 (fun _ -> `O [])) []];
  ignore (accepted "matchLabel contributes to predicate budget"
    [aggregate "empty" (List.init 512 (fun _ -> selector ["x","absent"])) []]);
  rejected "matchLabel budget excess" [aggregate "empty" (List.init 513 (fun _ -> selector ["x","absent"])) []];
  ignore (accepted "expression values contribute to predicate budget"
    [aggregate "empty" [expressions [expression ~values:(List.init 1022 (fun _ -> "x")) "label" "In"]] []]);
  rejected "expression value budget excess"
    [aggregate "empty" [expressions [expression ~values:(List.init 1023 (fun _ -> "x")) "label" "In"]] []];
  (* 102 ClusterRoles and 202 selector units fit their independent bounds.
     Each of 101 aggregates consumes 1,000 distinct rules from the same leaf,
     so normalization cannot erase the 101,000 edge contributions. *)
  let leaf_rules = List.init 1000 (fun i -> resource ~names:["n" ^ string_of_int i] ()) in
  let contribution_inventory = role ~labels:["budget","leaf"] "budget-leaf" leaf_rules ::
    List.init 101 (fun i -> aggregate ("budget-" ^ string_of_int i) [selector ["budget","leaf"]] leaf_rules) in
  let contribution_bytes = json (snapshot contribution_inventory) in
  check "contribution control fits independent input byte limit" (String.length contribution_bytes < 16 * 1024 * 1024);
  (match K.Snapshot.of_string contribution_bytes with
   | Ok _ -> failwith "rule contribution budget was not enforced"
   | Error reason -> check "contribution budget rejects rather than a different input boundary"
       (String.starts_with ~prefix:"manifest: aggregation rule contribution budget" reason));

  let source = json (snapshot mixed_items) in
  let prepared = K.Prepare.of_string source |> ok in
  check "preparation preserves aggregate fields and complete policy" (normalize (parse prepared.snapshot)=normalize (parse source));
  let manifest = K.Prepare.of_manifest ~format:K.Manifest_input.Json source |> ok |> K.Prepare.manifest_snapshot in
  check "manifest preparation preserves every rule and selector" (normalize (parse manifest.snapshot)=normalize (parse source));
  let a = json (snapshot [mixed;binding "reader" "aggregate"]) and b = json (snapshot [mixed_leaf]) in
  let descriptor id bytes = `O ["id",`String id;"path",`String (id ^ ".json");"format",`String "json";
    "sha256",`String (Soundcheck_core.Sha256.string bytes);"source_type",`String "supplied"] in
  let plan = json (`O ["schema_version",`Number "1";"kind",`String "kubernetes-rbac-inventory";
    "sources",`A [descriptor "aggregate" a;descriptor "contributors" b]]) in
  let inventory = K.Inventory.assemble ~load:(function "aggregate.json" -> a | "contributors.json" -> b | _ -> assert false) plan |> ok in
  check "cross-source contributors are resolved after assembly" (inventory.object_count=3);
  check "cross-source assembly retains source ordering" (normalize (parse inventory.snapshot)=
    normalize (snapshot [mixed;binding "reader" "aggregate";mixed_leaf]));
  let receipt = parse inventory.receipt in
  check "receipt still makes no verification claim" (field "verification_performed" receipt=`Bool false);
  check "receipt does not establish inventory completeness" (field "completeness_established" receipt=`Bool false);
  check "receipt binds complete assembled input" (field "sha256" (field "snapshot" receipt)=
    `String (Soundcheck_core.Sha256.string inventory.snapshot));
  Printf.printf "RBAC aggregate snapshots: %d checks passed.\n" !checks
