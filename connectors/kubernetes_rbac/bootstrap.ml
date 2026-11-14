open Input

type t = { snapshot : string; receipt : string; object_count : int }
let kubernetes_version = "1.34.0"
let available_packs = ["auth-delegator";"cluster-admin";"extension-apiserver-authentication-reader";"view"]
let strings values = `A (List.map (fun value -> `String value) values)
let number value = `Number (string_of_int value)
let identity bytes = `O ["sha256",`String (Soundcheck_core.Sha256.string bytes);"bytes",number (String.length bytes)]

let object_identity path value =
  let fields = obj path ["apiVersion";"kind";"metadata";"rules";"aggregationRule"] value in
  require_equal (path ^ ".apiVersion") (string_field path "apiVersion" fields) "rbac.authorization.k8s.io/v1";
  let kind = string_field path "kind" fields in
  if not (List.mem kind ["Role";"ClusterRole"]) then reject path "bootstrap packs may contain roles only";
  let metadata = field path "metadata" fields in
  let metadata = match metadata with `O fields -> fields | _ -> reject path "metadata must be an object" in
  let name = string_field (path ^ ".metadata") "name" metadata in
  let ns = optional_string path "namespace" metadata in
  kind ^ "/" ^ (if ns="" then "" else ns ^ "/") ^ name

let prepare ~kubernetes_version:requested_version ~packs = protect (fun () ->
  require_equal "bootstrap.kubernetes_version" requested_version kubernetes_version;
  if packs=[] || List.length packs > List.length available_packs then
    reject "bootstrap.packs" "select between one and four explicit packs";
  let seen = Hashtbl.create (List.length packs) in
  List.iter (fun name ->
    if not (List.mem name available_packs) then reject "bootstrap.packs" ("unknown pack " ^ name);
    if Hashtbl.mem seen name then reject "bootstrap.packs" ("duplicate pack " ^ name);
    Hashtbl.add seen name ()) packs;
  if Soundcheck_core.Sha256.string Bootstrap_data.json <> Bootstrap_data.sha256 then
    reject "bootstrap" "embedded reference checksum mismatch";
  let source = obj "bootstrap.reference"
    ["schema_version";"kind";"kubernetes_version";"upstream";"configuration";"source_catalogue";"aggregation";"packs"]
    (parse Bootstrap_data.json) in
  if field "bootstrap.reference" "schema_version" source <> `Number "1" then reject "bootstrap.reference" "unexpected source schema";
  require_equal "bootstrap.reference.kind" (string_field "bootstrap.reference" "kind" source) "kubernetes-bootstrap-reference-packs";
  require_equal "bootstrap.reference.version" (string_field "bootstrap.reference" "kubernetes_version" source) kubernetes_version;
  let rows = field "bootstrap.reference" "packs" source |> arr "bootstrap.reference.packs" in
  let rows = List.mapi (fun index value ->
    let path = Printf.sprintf "bootstrap.reference.packs[%d]" index in
    let row = obj path ["name";"requested_objects";"dependency_objects";"objects"] value in
    let name = string_field path "name" row in
    let requested = field path "requested_objects" row |> arr path |> List.map (str path) in
    let dependencies = field path "dependency_objects" row |> arr path |> List.map (str path) in
    let objects = field path "objects" row |> arr path in
    let ids = List.map (object_identity path) objects in
    if ids <> requested @ dependencies || requested=[] then reject path "declared object selection differs from pack policy";
    name,(value,objects,requested,dependencies)) rows in
  if List.map fst rows <> available_packs then reject "bootstrap.reference" "unexpected embedded pack catalogue";
  let selected = List.sort String.compare packs |> List.map (fun name -> name,List.assoc name rows) in
  let items = List.concat_map (fun (_,(_,objects,_,_)) -> objects) selected in
  let raw = json (`O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items]) ^ "\n" in
  let normalized = match Prepare.of_manifest ~format:Manifest_input.Json raw with
    | Ok prepared -> prepared
    | Error reason -> reject "bootstrap.reference" reason in
  let prepared = Prepare.manifest_snapshot normalized in
  let objects = List.concat_map (fun (name,(_,_,requested,dependencies)) ->
    List.map (fun id -> `O ["identity",`String id;"pack",`String name;
      "selection",`String "requested"]) requested @
    List.map (fun id -> `O ["identity",`String id;"pack",`String name;
      "selection",`String "aggregation-dependency"]) dependencies) selected in
  let receipt = json (`O ["schema_version",number 1;"kind",`String "rbac-bootstrap-selection";
    "kubernetes_version",`String kubernetes_version;"requested_packs",strings packs;
    "selected_packs",strings (List.map fst selected);"reference",identity Bootstrap_data.json;
    "upstream",field "bootstrap.reference" "upstream" source;
    "configuration",field "bootstrap.reference" "configuration" source;
    "source_catalogue",field "bootstrap.reference" "source_catalogue" source;
    "objects",`A objects;"normalization",parse (Prepare.manifest_receipt_json normalized);
    "snapshot",identity prepared.snapshot;"object_count",number prepared.object_count;
    "verification_performed",`Bool false;"installed_state_observed",`Bool false;
    "identity_authentication_established",`Bool false;"completeness_established",`Bool false;
    "limitations",strings [
      "Explicit upstream bootstrap reference assumptions; installed roles and feature gates may differ.";
      "No bindings or identity/group information are generated and no missing roleRef is automatically resolved.";
      "The view pack contains only its pinned bootstrap contributors; additional selected roles require reviewed materialized policy.";
      "Assembly rejects duplicate role identities and inconsistent aggregates; these packs never overwrite supplied policy.";
      "Review all inventory sources and CRD metadata independently before freezing requirements."]]) in
  {snapshot=prepared.snapshot;receipt;object_count=prepared.object_count})
