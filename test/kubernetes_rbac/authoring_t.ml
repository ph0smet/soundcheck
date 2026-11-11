module K = Soundcheck_kubernetes_rbac
open K.Input
open Soundcheck_core

let checks = ref 0
let check label ok = incr checks; if not ok then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let contains text needle =
  let rec go i = i+String.length needle<=String.length text &&
    (String.sub text i (String.length needle)=needle || go (i+1)) in go 0
let fields = function `O fields -> fields | _ -> failwith "object expected"
let array = function `A values -> values | _ -> failwith "array expected"
let get key value = List.assoc key (fields value)
let set key value source = `O ((key,value)::List.remove_assoc key (fields source))
let strings values = `A (List.map (fun value -> `String value) values)
let read path = let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () -> really_input_string channel (in_channel_length channel))
let base version =
  let clause name kind resource = `O (["name",`String name;"kind",`String kind;
    "subject",`String "alice";"namespace",`String "apps";"resource",`String resource;"names",`Null]
    @ if version=1 then [] else ["verb",`String "get"]) in
  `O ["schema_version",`Number (string_of_int version);"kind",`String "kubernetes-rbac-access";
    "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
      "identities",`A [`O ["username",`String "alice";"groups",strings ["team"]]]];
    "clauses",`A [clause "required" "must_allow" "configmaps";clause "forbidden" "must_not_grant" "secrets"];
    "change_scope",`A []]
let first f contract = match get "clauses" contract |> array with
  | one::rest -> set "clauses" (`A (f one::rest)) contract | [] -> assert false
let error source fragments =
  match K.Contract_spec.of_string (json source) with
  | Ok _ -> failwith "invalid authoring input accepted"
  | Error reason -> List.iter (fun part -> check (reason ^ " should contain " ^ part) (contains reason part)) fragments

let () =
  List.iter (fun version ->
    let source = json (base version) in
    let spec = K.Contract_spec.of_string source |> ok in
    let canonical = K.Contract_spec.canonical spec in
    let review = K.Contract_review.run source |> ok in
    List.iter (fun text -> check ("review: " ^ text) (contains review text))
      ["structure only; not a verification result";"have NOT been checked";
       "Contract schema: " ^ string_of_int version;K.Assurance.id_for_version version;
       "Raw artifact SHA-256: " ^ Sha256.string source;
       "Canonical frozen-contract SHA-256: " ^ Sha256.string canonical;
       "1 identities; 1 group memberships; 2 clauses (1 must_allow, 1 must_not_grant); 0 normalized";
       "None. Preserve every modeled decision";"not measured authoring effort"];
    let descriptions = List.map Contract.description (K.Contract_spec.to_contract spec).clauses in
    check "existing report wording retained" (descriptions = [
      "RBAC must grant get for \"alice\" on core configmaps in namespace \"apps\" (all valid names)";
      "RBAC must not grant get for \"alice\" on core secrets in namespace \"apps\" (all valid names)"]);
    check "whitespace affects only raw review identity"
      (contains (K.Contract_review.run (source ^ "\n") |> ok) ("Canonical frozen-contract SHA-256: " ^ Sha256.string canonical))) [1;2;3;4];
  let change key value = first (set key value) (base 4) in
  error (change "subject" (`String "reader\nwrong")) ["contract.clauses[0].subject";"reader\\nwrong";"context.identities[].username"];
  error (change "namespace" `Null) [".namespace";"all-namespace list/watch endpoint";"not every named namespace"];
  error (change "namespace" (`String "*")) [".namespace";"not a namespace wildcard"];
  error (first (set "namespace" (`O ["include",strings ["apps"]])) (base 3)) [".namespace";"schema 4";"separate requirement review"];
  error (change "namespace" (`O ["include",strings ["apps";"*"]])) [".namespace.include[1]";"literals, not wildcards"];
  error (change "namespace" (`O ["exclude",strings ["apps";"apps"]])) [".namespace.exclude[1]";"duplicate selector value"];
  error (change "namespace" (`O ["include",`A []])) [".namespace.include";"must not be empty"];
  error (change "names" (`A [])) [".names";"empty list";"names:null";"empty:true"];
  List.iter (fun name -> error (change "names" (strings [name])) [".names[0]";"DNS1123 object name"])
    ["";"*";"Invalid"];
  error (change "names" (strings ["settings";"settings"])) [".names[1]";"duplicate selector value"];
  error (first (set "names" (`O ["empty",`Bool true])) (base 2)) [".names";"schema 4"];
  error (change "names" (`O ["empty",`Bool true])) [".names.empty";"list/watch";"cannot select named"];
  error (change "names" (`O ["exclude",strings [];"include_empty",`Bool true])) [".names.include_empty";"only list/watch"];
  error (first (set "verb" (`String "patch")) (base 2)) [".verb";"schema 2";"get, list, watch"];
  error (change "verb" (`String "create")) [".verb";"schema 4";"Do not substitute"];
  error (change "resource" (`String "pods/log")) [".resource";"pods/log";"no API-group prefix or subresource"];
  error (set "context" (set "snapshot_complete" (`Bool false) (get "context" (base 4))) (base 4))
    ["context.snapshot_complete";"independently established complete inventory";"does not establish completeness"];
  let identities = get "identities" (get "context" (base 4)) |> array in
  error (set "context" (set "identities" (`A (identities@identities)) (get "context" (base 4))) (base 4))
    ["context.identities[1].username";"duplicate username \"alice\""];
  let root = Sys.argv.(1) in
  let source = read (Filename.concat root "contract.json") in
  let spec = K.Contract_spec.of_string source |> ok in
  check "fixed independent example contract" (Sha256.string (K.Contract_spec.canonical spec)=
    "afb1b0805f445c27bf152342b432afad00443df4845f1f7dc99370817ebdfb5d");
  let review = K.Contract_review.run source |> ok in
  List.iter (fun text -> check text (contains review text))
    ["2 identities; 5 group memberships; 3 clauses (1 must_allow, 2 must_not_grant); 2 normalized";
     "in namespaces \"team-a\", \"team-b\"";"every valid nonempty namespace except";
     "any valid nonempty name except \"settings\"";"candidate access requirements still apply inside them"];
  let baseline = read (Filename.concat root "unsafe.json") in
  List.iter (fun (name,expected) ->
    let input = read (Filename.concat root (name ^ ".json")) in
    let report = K.Verify.run spec input in
    check (name ^ " ordered verdict") (match expected,report.result,report.clause with
      | None,Report.Proved,None -> true
      | Some expected,Report.Violated _,Some clause -> clause.name=expected
      | _ -> false);
    let comparison = K.Verify.compare_with_trace spec ~before:baseline ~after:input in
    check (name ^ " comparison") (match name,comparison.report.result,comparison.report.clause with
      | "repaired",Report.Proved,None -> true
      | "operator-regression",Report.Violated witness,Some clause ->
        clause.kind=Report.Must_preserve && witness.principal="operator" && witness.action="get"
        && witness.object_request=Some {namespace="ops";resource_kind="configmaps";name="status"}
      | _,Report.Violated _,Some clause -> Some clause.name=expected
      | _ -> false))
    ["unsafe",Some "other-names-forbidden";"repaired",None;"deny-all",Some "settings-required";
     "operator-regression",None;"leftover-group",Some "other-names-forbidden"];
  let objects = get "items" (parse baseline) |> array in
  let snapshot items = json (`O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items]) in
  let snapshot_error items fragments = match K.Snapshot.of_string (snapshot items) with
    | Ok _ -> failwith "bad snapshot accepted"
    | Error reason -> List.iter (fun part -> check part (contains reason part)) fragments in
  snapshot_error (objects @ [List.hd objects]) ["manifest.items[4]";"duplicate RBAC object identity ClusterRole";"first supplied at items[0]"];
  snapshot_error [set "aggregationRule" (`O ["clusterRoleSelectors",`A [`O []]]) (List.hd objects)]
    [".rules";"stored rules";"aggregation controllers";"do not remove"];
  snapshot_error [List.nth objects 1;List.nth objects 3]
    ["items[0] ClusterRoleBinding/config-reader-global -> ClusterRole/config-reader";
     "items[1] RoleBinding/ops/status-reader -> Role/ops/status-reader";"rbac inventory";"does not establish completeness"];
  Printf.printf "RBAC authoring and diagnostics: %d checks passed.\n" !checks
