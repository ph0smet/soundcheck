module K = Soundcheck_kubernetes_rbac
module P = K.Policy_coverage
module S = K.Snapshot

let checks = ref 0
let check name condition = incr checks; if not condition then failwith ("policy coverage: " ^ name)
let ok = function Ok value -> value | Error reason -> failwith reason
let rr ?(verbs=["get"]) ?(groups=[""]) ?(resources=["pods"]) ?(names=[]) () =
  S.Resource { verbs; api_groups=groups; resources; resource_names=names }
let nr ?(verbs=["get"]) urls = S.Non_resource { verbs; urls }
let missing report = List.map (fun (x:P.missing) -> x.rule) report.P.missing
let cover name owner proposed expected =
  let report = ok (P.covers ~owner ~proposed) in
  check (name ^ " verdict") (report.covered = (expected = []));
  check (name ^ " missing atoms") (missing report = expected);
  report
let rejects name fragment value =
  check name (match value with
    | Error reason -> String.split_on_char '\n' reason |> List.exists (fun line ->
        let rec at i = i + String.length fragment <= String.length line &&
          (String.sub line i (String.length fragment)=fragment || at (i+1)) in at 0)
    | Ok _ -> false)

let rule_json = function
  | S.Resource r -> `O ["verbs",`A (List.map (fun s -> `String s) r.verbs);
      "apiGroups",`A (List.map (fun s -> `String s) r.api_groups);
      "resources",`A (List.map (fun s -> `String s) r.resources);
      "resourceNames",`A (List.map (fun s -> `String s) r.resource_names)]
  | S.Non_resource r -> `O ["verbs",`A (List.map (fun s -> `String s) r.verbs);
      "nonResourceURLs",`A (List.map (fun s -> `String s) r.urls)]
let role ?(namespace="") kind name rules =
  `O ["apiVersion",`String K.Input.api_version;"kind",`String kind;
      "metadata",`O ["name",`String name;"namespace",`String namespace];
      "rules",`A (List.map rule_json rules)]
let subject kind name = `O ["kind",`String kind;"apiGroup",`String K.Input.group;"name",`String name]
let service_account ?namespace name =
  `O (["kind",`String "ServiceAccount";"name",`String name] @
      match namespace with None -> [] | Some ns -> ["namespace",`String ns])
let binding ?(namespace="") kind name target_kind target_name subjects =
  `O ["apiVersion",`String K.Input.api_version;"kind",`String kind;
      "metadata",`O ["name",`String name;"namespace",`String namespace];
      "subjects",`A subjects;"roleRef",`O ["apiGroup",`String K.Input.group;
      "kind",`String target_kind;"name",`String target_name]]
let snapshot items =
  K.Input.json (`O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items])
  |> S.of_string |> ok
let identity ?(groups=[]) username : K.Identity.identity = { username; groups }

let () =
  let empty = cover "empty policy" [] [] [] in
  check "empty policy has zero atoms" (empty.atom_count=0);
  ignore (cover "exact arbitrary API" [rr ~groups:["widgets.example.net"] ~resources:["widgets/diagnose"] ~verbs:["frob"] ()]
    [rr ~groups:["widgets.example.net"] ~resources:["widgets/diagnose"] ~verbs:["frob"] ()] []);
  ignore (cover "custom verb is not discarded" [rr ()] [rr ~verbs:["frob"] ()] [rr ~verbs:["frob"] ()]);
  ignore (cover "unknown group is not discarded" [rr ()] [rr ~groups:["unknown"] ()] [rr ~groups:["unknown"] ()]);
  ignore (cover "unknown resource is not discarded" [rr ()] [rr ~resources:["unknown"] ()] [rr ~resources:["unknown"] ()]);
  ignore (cover "unreachable strings still counted" [] [rr ~verbs:[""] ~groups:[""] ~resources:[""] ~names:[""] ()]
    [rr ~verbs:[""] ~groups:[""] ~resources:[""] ~names:[""] ()]);
  ignore (cover "case remains literal" [rr ~verbs:["GET"] ()] [rr ()] [rr ()]);
  ignore (cover "Unicode remains literal" [rr ~groups:["custom.λ"] ~resources:["数据"] ()]
    [rr ~groups:["custom.λ"] ~resources:["数据"] ()] []);

  let proposal = rr ~groups:["a";"b"] ~resources:["pods";"secrets"] ~verbs:["get";"update"] () in
  let owners = [
    rr ~groups:["a";"b"] ~resources:["pods";"secrets"] ~verbs:["get"] ();
    rr ~groups:["a"] ~resources:["pods";"secrets"] ~verbs:["update"] ();
    rr ~groups:["b"] ~resources:["pods"] ~verbs:["update"] ()] in
  let split = cover "split union covers each complete atom" owners [proposal]
    [rr ~groups:["b"] ~resources:["secrets"] ~verbs:["update"] ()] in
  check "full cross-product atom count" (split.atom_count=8);
  check "exact local atom position" (List.map (fun (m:P.missing) -> m.proposed_rule_index,m.atom_index) split.missing=[0,7]);
  ignore (cover "remaining atom completes split union"
    (owners @ [rr ~groups:["b"] ~resources:["secrets"] ~verbs:["update"] ()]) [proposal] []);
  ignore (cover "dimensions cannot mix across owner rules"
    [rr ~groups:["a"] ~resources:["pods"] ~verbs:["get"] ();
     rr ~groups:["b"] ~resources:["secrets"] ~verbs:["update"] ()]
    [rr ~groups:["a"] ~resources:["secrets"] ~verbs:["get"] ()]
    [rr ~groups:["a"] ~resources:["secrets"] ~verbs:["get"] ()]);
  List.iter (fun proposed -> ignore (cover "full resource wildcards" [rr ~verbs:["*"] ~groups:["*"] ~resources:["*"] ()] [proposed] []))
    [proposal;rr ~verbs:["*"] ~groups:["*"] ~resources:["*"] ();rr ~verbs:[""] ~resources:["odd/a/b"] ()];
  List.iter (fun proposed -> ignore (cover "finite values do not cover wildcard" [proposal] [proposed] [proposed]))
    [rr ~groups:["*"] ~resources:["pods"] ();rr ~groups:["a"] ~resources:["*"] ();
     rr ~groups:["a"] ~verbs:["*"] ()];

  ignore (cover "unrestricted names cover each selected name" [rr ()] [rr ~names:["alpha";"beta"] ()] []);
  ignore (cover "split named grants form a union" [rr ~names:["alpha"] ();rr ~names:["beta"] ()]
    [rr ~names:["alpha";"beta"] ()] []);
  ignore (cover "finite names never cover unrestricted" [rr ~names:["alpha";"beta"] ()] [rr ()] [rr ()]);
  ignore (cover "star name is literal" [rr ~names:["*"] ()] [rr ~names:["alpha"] ()] [rr ~names:["alpha"] ()]);
  ignore (cover "star name equals itself" [rr ~names:["*"] ()] [rr ~names:["*"] ()] []);
  ignore (cover "star name does not cover unrestricted" [rr ~names:["*"] ()] [rr ()] [rr ()]);
  ignore (cover "empty name equals itself" [rr ~names:[""] ()] [rr ~names:[""] ()] []);
  ignore (cover "empty name remains restricted" [rr ~names:[""] ()] [rr ()] [rr ()]);
  ignore (cover "named create policy is not projected away" [] [rr ~verbs:["create"] ~names:["alpha"] ()]
    [rr ~verbs:["create"] ~names:["alpha"] ()]);

  List.iter (fun (owner,proposed,covered) ->
    let target = rr ~resources:[proposed] () in
    ignore (cover ("resource pattern " ^ owner ^ " -> " ^ proposed)
      [rr ~resources:[owner] ()] [target] (if covered then [] else [target])))
    ["*/exec","pods/exec",true; "*/exec","pods",false;
     "pods/*","pods/exec",false; "pods/*","pods/*",true;
     "*/a/b","pods/a/b",true; "*/b","pods/a/b",false;
     "*/","pods/",true; "*","*/exec",true;
     "pods/exec","*/exec",false; "*/*","pods/exec",false;
     "*/*","pods/*",true; "pods","pods/exec",false];

  List.iter (fun (owner,proposed,covered) ->
    let target=nr [proposed] in
    ignore (cover ("URL pattern " ^ owner ^ " -> " ^ proposed)
      [nr [owner]] [target] (if covered then [] else [target])))
    ["*","",true; "*","/",true; "/*","",false;
     "/api/*","/api",false; "/api/*","/api/",true;
     "/api/**","/api/",true; "/api/**","/api/v1*",true;
     "/api/**","/api*",false; "/api/*/x*","/api/v1/x",false;
     "/api/*/x*","/api/*/xyz",true; "/api/*/x*","/api/*/x*",true;
     "/api","/api",true; "/API","/api",false;
     "**","no-slash",true; "","",true;
     "/apis/*","*",false; "/api/*","/api/*/v1",true];
  ignore (cover "split URL verbs and paths"
    [nr ~verbs:["get"] ["/a";"/b"];nr ~verbs:["post"] ["/a"]]
    [nr ~verbs:["get";"post"] ["/a";"/b"]] [nr ~verbs:["post"] ["/b"]]);
  ignore (cover "resource wildcard does not authorize URLs" [rr ~verbs:["*"] ~groups:["*"] ~resources:["*"] ()]
    [nr ["/api"]] [nr ["/api"]]);
  ignore (cover "URL wildcard does not authorize resources" [nr ~verbs:["*"] ["*"]] [rr ()] [rr ()]);

  let duplicates = cover "duplicates preserved" []
    [rr ~groups:["a";"a"] ~verbs:["get";"get"] ~names:["x";"x"] (); nr ~verbs:["get";"get"] ["/a";"/a"]]
    (List.init 8 (fun _ -> rr ~groups:["a"] ~names:["x"] ()) @ List.init 4 (fun _ -> nr ["/a"])) in
  check "duplicate count" (duplicates.atom_count=12);
  check "atom indices restart per source rule"
    (List.map (fun (m:P.missing) -> m.proposed_rule_index,m.atom_index) duplicates.missing =
      List.init 8 (fun i -> 0,i) @ List.init 4 (fun i -> 1,i));
  let ordered = ok (P.covers ~owner:[] ~proposed:
    [rr ~groups:["g0";"g1"] ~resources:["r0";"r1"] ~verbs:["v0";"v1"] ~names:["n0";"n1"] ()]) in
  check "native nested iteration order"
    (missing ordered = [
      rr ~groups:["g0"] ~resources:["r0"] ~verbs:["v0"] ~names:["n0"] ();
      rr ~groups:["g0"] ~resources:["r0"] ~verbs:["v0"] ~names:["n1"] ();
      rr ~groups:["g0"] ~resources:["r0"] ~verbs:["v1"] ~names:["n0"] ();
      rr ~groups:["g0"] ~resources:["r0"] ~verbs:["v1"] ~names:["n1"] ();
      rr ~groups:["g0"] ~resources:["r1"] ~verbs:["v0"] ~names:["n0"] ();
      rr ~groups:["g0"] ~resources:["r1"] ~verbs:["v0"] ~names:["n1"] ();
      rr ~groups:["g0"] ~resources:["r1"] ~verbs:["v1"] ~names:["n0"] ();
      rr ~groups:["g0"] ~resources:["r1"] ~verbs:["v1"] ~names:["n1"] ();
      rr ~groups:["g1"] ~resources:["r0"] ~verbs:["v0"] ~names:["n0"] ();
      rr ~groups:["g1"] ~resources:["r0"] ~verbs:["v0"] ~names:["n1"] ();
      rr ~groups:["g1"] ~resources:["r0"] ~verbs:["v1"] ~names:["n0"] ();
      rr ~groups:["g1"] ~resources:["r0"] ~verbs:["v1"] ~names:["n1"] ();
      rr ~groups:["g1"] ~resources:["r1"] ~verbs:["v0"] ~names:["n0"] ();
      rr ~groups:["g1"] ~resources:["r1"] ~verbs:["v0"] ~names:["n1"] ();
      rr ~groups:["g1"] ~resources:["r1"] ~verbs:["v1"] ~names:["n0"] ();
      rr ~groups:["g1"] ~resources:["r1"] ~verbs:["v1"] ~names:["n1"] ()]);

  List.iter (fun malformed ->
    rejects "malformed proposal rejected" "must not be empty" (P.covers ~owner:[] ~proposed:[malformed]);
    rejects "malformed owner after wildcard rejected" "must not be empty"
      (P.covers ~owner:[rr ~verbs:["*"] ~groups:["*"] ~resources:["*"] ();malformed] ~proposed:[rr ()]);
    rejects "empty proposal still validates owner" "must not be empty" (P.covers ~owner:[malformed] ~proposed:[]))
    [rr ~verbs:[] ();rr ~groups:[] ();rr ~resources:[] ();nr ~verbs:[] ["/a"];nr []];

  let attributes rules = P.granting_rules ~rules ~verb:"get" ~api_group:"" ~resource:"pods" ~subresource:"exec" ~name:"a" in
  let ordinary = [nr ~verbs:["*"] ["*"]; rr ~resources:["pods"] ();
    rr ~resources:["pods/exec"] ~names:["a"] ();rr ~resources:["*/exec"] ();
    rr ~resources:["pods/*"] ();rr ~resources:["*"] ~names:["*"] ();
    rr ~resources:["pods/exec"] ~names:["a"] ()] in
  check "ordinary matching indices and duplicate rules" (ok (attributes ordinary)=[2;3;6]);
  check "ordinary wildcard name is literal" (ok (P.granting_rules ~rules:[rr ~resources:["*"] ~names:["*"] ()]
    ~verb:"get" ~api_group:"" ~resource:"pods" ~subresource:"" ~name:"*")=[0]);
  check "ordinary empty request name remains exact" (ok (P.granting_rules ~rules:[rr ~verbs:["create"] ~names:["a"] ();
    rr ~verbs:["create"] ~names:[""] ();rr ~verbs:["create"] ()]
    ~verb:"create" ~api_group:"" ~resource:"pods" ~subresource:"" ~name:"")=[1;2]);
  check "ordinary subresource is supplied, not inferred from resource"
    (ok (P.granting_rules ~rules:[rr ~resources:["*/exec"] ()] ~verb:"get" ~api_group:""
      ~resource:"pods/exec" ~subresource:"" ~name:"a")=[]);
  check "ordinary full subresource suffix retained"
    (ok (P.granting_rules ~rules:[rr ~resources:["*/a/b"] ()] ~verb:"get" ~api_group:""
      ~resource:"pods" ~subresource:"a/b" ~name:"a")=[0]);
  check "ordinary arbitrary attributes preserved"
    (ok (P.allows_resource ~rules:[rr ~groups:["custom"] ~verbs:["frob"] ~resources:["widgets"] ()]
      ~verb:"frob" ~api_group:"custom" ~resource:"widgets" ~subresource:"" ~name:"x"));
  check "ordinary absence is nonallowance"
    (not (ok (P.allows_resource ~rules:[] ~verb:"get" ~api_group:"" ~resource:"pods" ~subresource:"" ~name:"a")));
  rejects "ordinary validation does not short circuit after grant" "must not be empty"
    (attributes [rr ~resources:["*"] ();nr []]);

  let global = [rr ~resources:["unknown.cluster.resource"] ();nr ["/cluster/*"]] in
  let scoped = [rr ~verbs:["frob"] ~groups:["custom"] ~resources:["cluster-only"] ();nr ["/namespace-bound/*"]] in
  let local = rr ~verbs:["update"] ~resources:["configmaps"] () in
  let elsewhere = rr ~verbs:["delete"] ~resources:["configmaps"] () in
  let authenticated = rr ~verbs:["authenticate-only"] () in
  let baseline = snapshot [
    role "ClusterRole" "global" global;role "ClusterRole" "scoped" scoped;
    role "ClusterRole" "authenticated" [authenticated];
    role ~namespace:"apps" "Role" "local" [local];role ~namespace:"other" "Role" "local" [elsewhere];
    role "ClusterRole" "unbound" [rr ~resources:["*"] ~verbs:["*"] ~groups:["*"] ()];
    binding ~namespace:"apps" "RoleBinding" "before-cluster" "Role" "local" [subject "User" "alice"];
    binding ~namespace:"other" "RoleBinding" "other" "Role" "local" [subject "User" "alice"];
    binding "ClusterRoleBinding" "global" "ClusterRole" "global" [subject "User" "alice"];
    binding ~namespace:"apps" "RoleBinding" "group" "ClusterRole" "scoped" [subject "Group" "devs"];
    binding "ClusterRoleBinding" "unmatched" "ClusterRole" "global" [subject "Group" "admins"];
    binding "ClusterRoleBinding" "sa" "ClusterRole" "global" [service_account ~namespace:"apps" "worker"];
    binding "ClusterRoleBinding" "authenticated" "ClusterRole" "authenticated" [subject "Group" "system:authenticated"];
    binding ~namespace:"apps" "RoleBinding" "sa-default" "Role" "local" [service_account "worker"];
    binding ~namespace:"apps" "RoleBinding" "two-subjects" "Role" "local" [subject "User" "alice";subject "Group" "devs"]] in
  let resolve ?(groups=[]) who namespace = ok (P.rules_for baseline ~identity:(identity ~groups who) ~namespace) in
  check "RulesFor cluster bindings precede earlier role bindings and preserve full policy"
    (resolve ~groups:["devs"] "alice" "apps" = global @ [local] @ scoped @ [local]);
  check "one matching binding is counted once despite multiple matching subjects"
    (List.length (resolve ~groups:["devs"] "alice" "apps")=6);
  check "no group is inferred" (resolve "alice" "apps"=global @ [local;local]);
  check "empty namespace excludes all RoleBindings" (resolve ~groups:["devs"] "alice" ""=global);
  check "exact other namespace" (resolve ~groups:["devs"] "alice" "other"=global @ [elsewhere]);
  check "explicit authentication group only" (resolve ~groups:["system:authenticated"] "unbound-user" ""=[authenticated]);
  check "service-account exact username and local namespace default"
    (resolve "system:serviceaccount:apps:worker" "apps"=global @ [local]);
  check "service-account namespace remains exact" (resolve "system:serviceaccount:other:worker" "apps"=[]);
  check "service-account groups are not inferred" (resolve "system:serviceaccount:apps:worker" ""=global);
  check "unbound role confers no authority" (resolve "nobody" "apps"=[]);

  let sequence n = List.init n string_of_int in
  let largest = rr ~groups:(sequence 100) ~resources:(sequence 100) ~verbs:(sequence 10) () in
  let expanded = ok (P.covers ~owner:[] ~proposed:[largest]) in
  check "100000 atoms accepted without truncation" (expanded.atom_count=100_000 && List.length expanded.missing=100_000);
  check "last diagnostic retained" ((List.hd (List.rev expanded.missing)).atom_index=99_999);
  let proved = ok (P.covers ~owner:[rr ~groups:["*"] ~verbs:["*"] ~resources:["*"] ()] ~proposed:[largest]) in
  check "100000 atoms covered when within work bound" (proved.covered && proved.atom_count=100_000);
  rejects "atom limit checked before expansion" "proposed atoms"
    (P.covers ~owner:[] ~proposed:[rr ~groups:(sequence 100) ~resources:(sequence 101) ~verbs:(sequence 10) ()]);
  rejects "large cardinality product cannot overflow into proof" "proposed atoms"
    (P.covers ~owner:[] ~proposed:[rr ~groups:(List.init 24_999 (fun _ -> "g"))
      ~resources:(List.init 24_999 (fun _ -> "r")) ~verbs:(List.init 24_999 (fun _ -> "v"))
      ~names:(List.init 24_999 (fun _ -> "n")) ()]);
  rejects "comparison work checked before expansion" "comparison units"
    (P.covers ~owner:(List.init 10 (fun _ -> rr ())) ~proposed:[largest]);
  let exactly_values = nr ~verbs:(List.init 99_998 (fun _ -> "get")) [""] in
  check "100000 input values accepted" ((ok (P.covers ~owner:[] ~proposed:[exactly_values])).atom_count=99_998);
  rejects "input value limit does not truncate" "input values"
    (P.covers ~owner:[] ~proposed:[nr ~verbs:(List.init 99_999 (fun _ -> "get")) [""]]);
  let exact_bytes=String.make (8 * 1024 * 1024) 'x' in
  check "8MiB input bytes accepted when no comparisons needed"
    ((ok (P.covers ~owner:[nr ~verbs:[""] [exact_bytes]] ~proposed:[])).covered);
  rejects "input bytes always checked even with no proposal" "string bytes"
    (P.covers ~owner:[nr ~verbs:["x"] [exact_bytes]] ~proposed:[]);
  rejects "ordinary request attrs also count toward byte budget" "string bytes"
    (P.granting_rules ~rules:[] ~verb:"x" ~api_group:"" ~resource:exact_bytes ~subresource:"" ~name:"");
  rejects "ordinary rules cannot bypass comparison budget" "comparison units"
    (attributes [nr ~verbs:[""] [String.make 2_500_000 'x']]);
  rejects "ordinary nonmatching URL rules still count values" "input values"
    (attributes [nr ~verbs:(List.init 100_000 (fun _ -> "get")) ["/ignored"]]);
  let long = String.make 1_000_000 'x' in
  let ten = List.init 10 (fun _ -> "v") in
  List.iter (fun proposed ->
    rejects "expanded diagnostics bounded with empty owner" "expanded atom string bytes"
      (P.covers ~owner:[] ~proposed:[proposed]);
    rejects "expanded atom budget independent of coverage outcome" "expanded atom string bytes"
      (P.covers ~owner:[rr ~verbs:["*"] ~groups:["*"] ~resources:["*"] ();nr ~verbs:["*"] ["*"]] ~proposed:[proposed]))
    [rr ~resources:[long] ~verbs:ten ();rr ~groups:[long] ~verbs:ten ();
     rr ~verbs:[long] ~resources:ten ();rr ~names:[long] ~verbs:ten ();
     nr ~verbs:ten [long];nr ~verbs:[long] ten];
  check "expanded atom byte boundary retained without truncation"
    ((ok (P.covers ~owner:[] ~proposed:[rr ~verbs:[""] ~resources:[exact_bytes] ()])).atom_count=1);
  let repeated_long = rr ~resources:[String.make (7 * 1024 * 1024) 'x']
      ~verbs:(List.init 1000 (fun _ -> "get")) () in
  rejects "small input cannot multiply into gigabyte diagnostics" "expanded atom string bytes"
    (P.covers ~owner:[] ~proposed:[repeated_long]);
  let huge_role = role "ClusterRole" "large" [rr ~verbs:(List.init 25_000 (fun _ -> "get")) ()] in
  let repeated = snapshot (huge_role :: List.init 4 (fun i ->
    binding "ClusterRoleBinding" ("repeated-" ^ string_of_int i) "ClusterRole" "large" [subject "User" "bob"])) in
  rejects "RulesFor repeated-reference expansion bounded before copying" "input values"
    (P.rules_for repeated ~identity:(identity "bob") ~namespace:"");
  rejects "RulesFor unmatched grants also bounded" "input values"
    (P.rules_for repeated ~identity:(identity "alice") ~namespace:"");
  rejects "RulesFor caller groups bounded even with empty snapshot" "input values"
    (P.rules_for (snapshot []) ~identity:(identity ~groups:(List.init 100_000 (fun _ -> "g")) "alice") ~namespace:"");
  let many_subjects = List.init 1_500 (fun i -> subject "Group" ("absent-" ^ string_of_int i)) in
  let expensive = snapshot [role "ClusterRole" "small" [rr ()];
    binding "ClusterRoleBinding" "many-groups" "ClusterRole" "small" many_subjects] in
  rejects "RulesFor group cross-product comparison bounded" "subject comparison units"
    (P.rules_for expensive ~identity:(identity ~groups:(sequence 1_500) "alice") ~namespace:"");
  Printf.printf "policy coverage: %d checks passed\n" !checks
