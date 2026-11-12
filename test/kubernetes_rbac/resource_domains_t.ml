open Soundcheck_core
module K = Soundcheck_kubernetes_rbac
module I = K.Input

let checks = ref 0
let check label yes = incr checks; if not yes then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let strings xs = `A (List.map (fun x -> `String x) xs)
let set key value fields = (key,value) :: List.remove_assoc key fields
let verbs = ["get";"list";"watch";"update";"patch";"delete"]
let collection verb = List.mem verb ["list";"watch"]
(* These literal pairs and expectations are independent of the connector's
   catalogue. resource_kind is the connector-defined, lossless discriminator. *)
let resources = [
  "","configmaps","configmaps",false; "","secrets","secrets",false;
  "","pods","pods",false; "","services","services",false;
  "","endpoints","endpoints",false; "","nodes","nodes",true;
  "apps","deployments","deployments.apps",false;
  "discovery.k8s.io","endpointslices","endpointslices.discovery.k8s.io",false]
let scope ?(subject="app") ?(verb="get") ?(group="") ?(resource="configmaps")
    ?(ns=`String "team-a") ?(names=strings ["settings"]) () =
  ["subject",`String subject;"verb",`String verb;"api_group",`String group;
   "resource",`String resource;"namespace",ns;"names",names]
let contract ?(version=5) ?(allow=scope ())
    ?(deny=scope ~resource:"secrets" ~names:`Null ()) ?(changes=[]) () =
  let fields xs = if version=1 then List.remove_assoc "verb" (List.remove_assoc "api_group" xs)
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
    id group resource verb namespace name =
  `O ["id",`String id;"username",`String "app";"groups",strings groups;
    "apiGroup",`String group;"resource",`String resource;"verb",`String verb;
    "namespace",`String namespace;"name",`String name;
    "subresource",`String subresource;"resourceRequest",`Bool resource_request]
let evaluate s rows = K.Evaluate.requests s (I.json (`A rows))
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
     check (label^" checked obligation") (Witness.clause p clause r);
     check (label^" retained grant provenance") (ce.granting_rules=K.Lower.granting_rules p r)
   | _ -> ()); report
let compare label s before after expected =
  let result=K.Verify.compare_with_trace s ~before ~after in
  check (label^" verdict") (outcome result.report.result=expected);
  check (label^" candidate independently satisfies contract")
    ((Option.get result.candidate_report).result=Report.Proved);
  (match result.report.result with
   | Report.Violated ce ->
     check (label^" preservation witness") ((Option.get result.report.clause).kind=Report.Must_preserve);
     check (label^" actual decision difference outside change scope")
       (Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes s))
          (policy s before) (policy s after) (from_ce ce))
   | _ -> ()); result.report
let read path = let c=open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr c) (fun () -> really_input_string c (in_channel_length c))
let smt_answers text =
  let input=Filename.temp_file "rbac-resource-matrix-" ".smt2"
  and output=Filename.temp_file "rbac-resource-matrix-" ".out"
  and error=Filename.temp_file "rbac-resource-matrix-" ".err" in
  Fun.protect ~finally:(fun () -> List.iter Sys.remove [input;output;error]) (fun () ->
    let c=open_out_bin input in output_string c text;close_out c;
    let out=Unix.openfile output [Unix.O_WRONLY;Unix.O_TRUNC] 0o600
    and err=Unix.openfile error [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let pid=Unix.create_process "z3" [|"z3";"-smt2";input|] Unix.stdin out err in
    Unix.close out;Unix.close err;
    let _,status=Unix.waitpid [] pid in
    check "SMT matrix completed without diagnostics" (status=Unix.WEXITED 0 && read error="");
    String.split_on_char '\n' (read output) |> List.filter (fun s -> s<>"")
    |> List.map (function "true" -> true | "false" -> false | line -> failwith ("unexpected SMT matrix output: "^line)))

let () =
  (* Captured with the untouched f8f08b7 CLI before schema 5. Include compound
     selectors and permuted duplicate changes to detect canonical sort drift. *)
  let complex_v4 = ok (K.Contract_spec.of_string {|{
    "schema_version":4,"kind":"kubernetes-rbac-access",
    "context":{"schema_version":1,"snapshot_complete":true,"identities":[
      {"username":"unused","groups":[]},{"username":"app","groups":["z","a"]}]},
    "clauses":[
      {"name":"required","kind":"must_allow","subject":"app","verb":"list",
       "namespace":{"include":["team-b","team-a"]},"resource":"configmaps",
       "names":{"exclude":["z","a"],"include_empty":true}},
      {"name":"forbidden","kind":"must_not_grant","subject":"app","verb":"patch",
       "namespace":{"exclude":["team-b"]},"resource":"secrets",
       "names":{"exclude":["password"],"include_empty":false}}],
    "change_scope":[
      {"subject":"unused","verb":"get","namespace":"team-a","resource":"configmaps","names":["z","a"]},
      {"subject":"app","verb":"watch","namespace":null,"resource":"configmaps","names":{"empty":true}},
      {"subject":"app","verb":"list","namespace":{"include":["team-b","team-a"]},"resource":"configmaps","names":["z","a"]},
      {"subject":"app","verb":"patch","namespace":{"exclude":["team-b","team-a"]},"resource":"configmaps","names":{"exclude":["z","a"],"include_empty":false}},
      {"subject":"app","verb":"list","namespace":{"include":["team-a","team-b"]},"resource":"configmaps","names":["a","z"]}]
  }|}) in
  check "pre-v5 compound v4 frozen identity is unchanged"
    (Sha256.string (K.Contract_spec.canonical complex_v4)="5d96db5ff2bd2ece5d5a40d1bf723ffc797a70be077b4523090bc255979357a5"
     && List.length (K.Contract_spec.changes complex_v4)=4);
  let s=spec (contract ()) in
  check "v5 profile is explicit" (K.Assurance.id_for_version 5="kubernetes-rbac-v1.34-resource-read-write-v1");
  List.iter (fun version ->
    let selected=spec (contract ~version ()) in
    check "URL requests reject at the resource-request boundary before catalogue lookup"
      (match evaluate selected [request_json ~resource_request:false "url" "" "" "get" "" ""] with
       | Error reason -> String.ends_with ~suffix:"resourceRequest must be true" reason
       | Ok _ -> false)) [1;2;3;4;5];
  (* Literal frozen bytes from the established pre-v5 shape, not regenerated by
     another traversal of Contract_spec. This also retains the unused identity. *)
  List.iter (fun version ->
    let old=spec (contract ~version ()) in
    let verb=if version=1 then "" else ",\"verb\":\"get\"" in
    let expected=Printf.sprintf
      {|{"schema_version":%d,"kind":"kubernetes-rbac-access","context":{"schema_version":1,"snapshot_complete":true,"identities":[{"username":"app","groups":["operators"]},{"username":"unused","groups":[]}]},"clauses":[{"name":"required","kind":"must_allow","subject":"app","namespace":"team-a","resource":"configmaps","names":["settings"]%s},{"name":"forbidden","kind":"must_not_grant","subject":"app","namespace":"team-a","resource":"secrets","names":null%s}],"change_scope":[]}|}
      version verb verb in
    check "v1-v4 canonical bytes unchanged" (K.Contract_spec.canonical old=expected);
    List.iter (fun (group,raw,kind,cluster) ->
      let ns=if cluster then "" else "team-a" in
      let allowed=raw="configmaps" || raw="secrets" in
      check "legacy domains do not acquire resource types"
        (Ir.matches (K.Lower.domain old) (request kind "get" ns "settings")=allowed);
      check "legacy concrete inputs do not acquire resource types"
        (Result.is_ok (evaluate old [request_json "old" group raw "get" ns "settings"])=allowed)) resources;
    let value=contract ~version () in
    let with_field=match value with `O fields ->
      let clauses=I.arr "clauses" (List.assoc "clauses" fields) |> List.map (function
        | `O fields -> `O (set "api_group" (`String "") fields) | _ -> assert false) in
      `O (set "clauses" (`A clauses) fields) | _ -> assert false in
    check "old contracts still reject api_group, even core" (Result.is_error (parse with_field))) [1;2;3;4];
  let named_values=["settings",true;"1numeric",true;"a.b",true;String.make 253 'a',true;
    "",false;"Bad",false;"*",false;"a/b",false;String.make 254 'a',false] in
  let namespaces=["team-a",true;"other",true;String.make 63 'a',true;"",false;"Bad",false;"a.b",false;String.make 64 'a',false] in
  List.iter (fun (group,raw,kind,cluster) ->
    List.iter (fun verb -> List.iter (fun (ns,valid_ns) -> List.iter (fun (name,valid_name) ->
      let expected=(if cluster then ns="" else valid_ns || (collection verb && ns=""))
        && (valid_name || (collection verb && name="")) in
      check "finite resource domain, name and namespace boundaries"
        (Ir.matches (K.Lower.domain s) (request kind verb ns name)=expected);
      check "raw group/resource maps to the same bounded coordinate"
        (Result.is_ok (evaluate s [request_json "domain" group raw verb ns name])=expected)) named_values) namespaces) verbs;
    let ns=if cluster then `Null else `String "team-a" in
    List.iter (fun verb ->
      check "all approved resource verbs parse" (Result.is_ok (parse
        (contract ~allow:(scope ~verb ~group ~resource:raw ~ns ()) ())))) verbs) resources;
  let invalid_scopes=[
    scope () |> List.remove_assoc "api_group";
    scope () |> set "api_group" `Null;
    scope () |> set "api_group" (`String "*");
    scope ~group:"apps" ~resource:"pods" ();
    scope ~group:"apps/v1" ~resource:"deployments" ();
    scope ~group:"apps" ~resource:"deployments.apps" ();
    scope ~resource:"pods/log" ();
    scope ~resource:"namespaces" ~ns:`Null ();
    scope ~group:"example.com" ~resource:"widgets" ();
    scope ~resource:"nodes" ();
    scope ~resource:"nodes" ~ns:(`String "") ();
    scope ~resource:"nodes" ~ns:(`O ["exclude",strings []]) ();
    scope ~resource:"nodes" ~ns:(`O ["include",strings ["team-a"]]) ();
    scope ~resource:"nodes" ~ns:`Null ~names:(`O ["empty",`Bool true]) ();
    scope ~resource:"nodes" ~ns:`Null ~names:(`O ["exclude",strings [];"include_empty",`Bool true]) ();
    scope ~group:"apps" ~resource:"deployments" ~ns:`Null ();
    scope ~verb:"create" ();scope ~verb:"deletecollection" ();scope ~verb:"bind" ();
    ("api_group",`String "")::scope ()] in
  List.iter (fun selected ->
    check "invalid new clause rejected" (Result.is_error (parse (contract ~allow:selected ())));
    check "invalid approved changes rejected" (Result.is_error (parse (contract ~changes:[selected] ())))) invalid_scopes;
  List.iter (fun row -> check "malformed concrete dimensions reject rather than alias"
    (Result.is_error (evaluate s [row])))
    [request_json "bad" "apps" "deployments.apps" "get" "team-a" "settings";
     request_json "bad" "" "deployments" "get" "team-a" "settings";
     request_json "bad" "apps" "pods" "get" "team-a" "settings";
     request_json "bad" "*" "pods" "get" "team-a" "settings";
     request_json "bad" "" "namespaces" "get" "team-a" "team-a";
     request_json ~subresource:"status" "bad" "apps" "deployments" "get" "team-a" "settings";
     request_json ~resource_request:false "bad" "" "nodes" "get" "" "node-a";
     request_json ~groups:[] "bad" "" "nodes" "get" "" "node-a"];
  let selected=scope ~verb:"patch" ~group:"apps" ~resource:"deployments"
    ~ns:(`O ["exclude",strings ["team-b";"team-a"]])
    ~names:(`O ["exclude",strings ["z";"a"];"include_empty",`Bool false]) () in
  let selectors=spec (contract ~allow:selected ~changes:[selected;selected] ()) in
  let canonical=K.Contract_spec.canonical selectors in
  check "v5 selectors normalize without losing group" (canonical=K.Contract_spec.canonical
    (ok (K.Contract_spec.of_string canonical)) && List.length (K.Contract_spec.changes selectors)=1);
  let cases=[
    "Role binding scope",grant ~role:"Role" ~binding:"RoleBinding" "local" [rule ~groups:["*"] ["*"]],
      (fun (_,_,_,_) verb ns _ -> List.mem verb verbs && ns="team-a");
    "RoleBinding to ClusterRole",grant ~binding:"RoleBinding" "shared" [rule ~groups:["*"] ["*"]],
      (fun (_,_,_,_) _ ns _ -> ns="team-a");
    "all group and resource wildcards",grant "all" [rule ~groups:["*"] ["*"]],
      (fun _ _ _ _ -> true);
    "apps resource wildcard",grant "apps" [rule ~groups:["apps"] ["*"]],
      (fun (_,raw,_,_) _ _ _ -> raw="deployments");
    "resource is separate from group",grant "pods" [rule ~groups:["apps"] ["pods"]],
      (fun _ _ _ _ -> false);
    "group wildcard and named resource",grant "deployment" [rule ~groups:["*"] ["deployments"]],
      (fun (_,raw,_,_) _ _ _ -> raw="deployments");
    "qualified names and subresource rules do not alias",grant "aliases"
      [rule ~groups:["*"] ["deployments.apps";"pods/*";"*/status"]],(fun _ _ _ _ -> false);
    "literal resourceNames star",grant "star" [rule ~groups:["*"] ~names:["*"] ["*"]],
      (fun _ _ _ _ -> false);
    "literal resourceNames empty",grant "empty" [rule ~groups:["*"] ~names:[""] ["*"]],
      (fun _ _ _ name -> name="");
    "literal named patches",grant "named" [rule ~groups:["*"] ~verbs:["patch"] ~names:["settings"] ["*"]],
      (fun _ verb _ name -> verb="patch" && name="settings") ] in
  List.iter (fun (label,items,expected) ->
    let p=policy s (snapshot items) in
    let serial=ref 0 in
    let rows=List.concat_map (fun ((group,raw,kind,cluster) as resource) ->
      List.concat_map (fun verb ->
        let nss=if cluster then [""] else ["team-a";"other"] @ if collection verb then [""] else [] in
        List.concat_map (fun ns -> List.map (fun name ->
          incr serial;
          let wanted=expected resource verb ns name and r=request kind verb ns name in
          check (label^" concrete permission") (Ir.possibly_allows p r=wanted);
          check (label^" definite permission") (Ir.definitely_allows p r=wanted);
          request_json (string_of_int !serial) group raw verb ns name,wanted)
          (["settings";"other"] @ if collection verb then [""] else [])) nss) verbs) resources in
    let inputs=ok (evaluate s (List.map fst rows)) in
    let expected=List.concat_map (fun (_,allowed) -> [true;allowed]) rows in
    check (label^" production SMT matches independent decisions")
      (smt_answers (K.Evaluate.matrix_smt p inputs)=expected)) cases;
  let common=grant "config" [rule ~verbs:["get"] ~names:["settings"] ["configmaps"]] in
  let legacy=spec (contract ~version:4 ()) in
  List.iter (fun (group,raw,_,cluster) ->
    let before=snapshot (common @ grant ~subject:"unused" "extra" [rule ~groups:[group] ~verbs:["get"] ~names:["settings"] [raw]])
    and after=snapshot common in
    ignore (compare (raw^" old domain remains fixed") legacy before after "proved");
    ignore (compare (raw^" v5 preserves resources without a clause") s before after "violated");
    let change=scope ~subject:"unused" ~group ~resource:raw ~ns:(if cluster then `Null else `String "team-a") () in
    (* The unbound namespace class cannot approve every namespace granted by a
       ClusterRoleBinding, while Nodes have only their cluster scope. *)
    let changed=spec (contract ~changes:[change] ()) in
    ignore (compare (raw^" exact approved scope") changed before after (if cluster then "proved" else "violated")))
    ["","pods","pods",false;"","nodes","nodes",true;"apps","deployments","deployments.apps",false];
  let required=scope ~verb:"patch" ~group:"apps" ~resource:"deployments" ~names:(strings ["app"]) ()
  and forbidden=scope ~resource:"nodes" ~ns:`Null ~names:(strings ["node-a"]) () in
  let s=spec (contract ~allow:required ~deny:forbidden ~changes:[forbidden] ()) in
  let access=grant ~binding:"RoleBinding" "deployment" [rule ~groups:["apps"] ~verbs:["patch"] ~names:["app"] ["deployments"]] in
  let safe=snapshot access and unsafe=snapshot (access @ grant "nodes" [rule ~verbs:["get"] ~names:["node-a"] ["nodes"]]) in
  ignore (verify "required deployment grant" s safe "proved");
  ignore (verify "deny all cannot satisfy grouped requirement" s (snapshot []) "violated");
  let report=verify "forbidden Node grant" s unsafe "violated" in
  (match report.result with Report.Violated ce ->
     let c=Option.get ce.object_request in
     check "Node counterexample has cluster coordinates"
       (c.resource_kind="nodes" && c.namespace="" && c.name="node-a" && ce.action="get")
   | _ -> assert false);
  ignore (compare "remove only approved Node grant" s unsafe safe "proved");
  let wrong_group=snapshot (grant ~binding:"RoleBinding" "wrong-group"
    [rule ~groups:["extensions"] ~verbs:["patch"] ~names:["app"] ["deployments"]]) in
  let report=verify "wrong group cannot satisfy apps access" s wrong_group "violated" in
  (match report.result with Report.Violated ce ->
    check "grouped counterexample preserves its unambiguous kind"
      ((Option.get ce.object_request).resource_kind="deployments.apps")
   | _ -> assert false);
  Printf.printf "RBAC resource domains: %d checks passed\n" !checks
