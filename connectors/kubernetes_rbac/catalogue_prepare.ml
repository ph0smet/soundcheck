open Input

type t = { catalogue : string; receipt : string; object_count : int; excluded_count : int }
let object_fields path = function `O fields -> fields | _ -> reject path "expected object"
let boolean path = function `Bool b -> b | _ -> reject path "expected boolean"
let strings xs = `A (List.map (fun x -> `String x) xs)
let number n = `Number (string_of_int n)

let subresources path = function
  | None -> [],`O []
  | Some value ->
    let fields = obj path ["status";"scale"] value in
    (match List.assoc_opt "status" fields with
     | None -> () | Some value -> ignore (obj (path ^ ".status") [] value));
    (match List.assoc_opt "scale" fields with
     | None -> ()
     | Some value ->
       let p = path ^ ".scale" in
       let scale = obj p ["specReplicasPath";"statusReplicasPath";"labelSelectorPath"] value in
       List.iter (fun key -> ignore (string_field p key scale |> nonempty (p ^ "." ^ key)))
         ["specReplicasPath";"statusReplicasPath"];
       (match List.assoc_opt "labelSelectorPath" scale with
        | None -> () | Some value -> ignore (str (p ^ ".labelSelectorPath") value)));
    List.sort String.compare (List.map fst fields),`O (List.sort (fun (a,_) (b,_) -> String.compare a b) fields)

let crd path value =
  let fields = object_fields path value in
  require_equal (path ^ ".apiVersion") (string_field path "apiVersion" fields) "apiextensions.k8s.io/v1";
  let metadata = field path "metadata" fields |> object_fields (path ^ ".metadata") in
  let name = string_field (path ^ ".metadata") "name" metadata in
  if optional_string path "namespace" metadata <> "" then reject path "CRDs must be cluster-scoped";
  let spec = field path "spec" fields |> object_fields (path ^ ".spec") in
  let group = string_field path "group" spec in
  let names = field path "names" spec |> object_fields (path ^ ".spec.names") in
  let plural = string_field path "plural" names in
  require_equal (path ^ ".metadata.name") name (plural ^ "." ^ group);
  let scope = string_field path "scope" spec in
  let versions = field path "versions" spec |> arr (path ^ ".spec.versions") in
  if versions=[] then reject path "at least one version is required";
  let seen = Hashtbl.create (List.length versions) in
  let storage_count = ref 0 in
  let versions = List.mapi (fun i value ->
    let p = Printf.sprintf "%s.spec.versions[%d]" path i in
    let version = object_fields p value in
    let name = string_field p "name" version in
    if not (dns_label name) || Hashtbl.mem seen name then reject p "invalid or duplicate version name";
    Hashtbl.add seen name ();
    let served = boolean (p ^ ".served") (field p "served" version) in
    let storage = boolean (p ^ ".storage") (field p "storage" version) in
    if storage then incr storage_count;
    let subs,details = subresources (p ^ ".subresources") (List.assoc_opt "subresources" version) in
    served,subs,`O ["name",`String name;"served",`Bool served;"storage",`Bool storage;
      "subresources",details]) versions in
  if !storage_count<>1 then reject path "exactly one storage version is required";
  let served = List.filter (fun (served,_,_) -> served) versions in
  let subs = match served with
    | [] -> reject path "at least one served version is required"
    | (_,first,_)::rest ->
      if List.exists (fun (_,subs,_) -> subs<>first) rest then
        reject path "served versions disagree on status/scale availability; supply an independently reviewed catalogue instead";
      first in
  let entry = `O ["api_group",`String group;"resource",`String plural;
    "scope",`String scope;"subresources",strings subs] in
  let receipt = `O ["source_path",`String path;"name",`String name;
    "parsed_object_sha256",`String (Soundcheck_core.Sha256.string (json value));
    "versions",`A (List.map (fun (_,_,v) -> v) versions);"catalogue_entry",entry] in
  entry,receipt

let run ?(crd_only=false) ~format source = protect (fun () ->
  let documents = Manifest_input.parse format source in
  let accepted = ref [] and excluded = ref [] and empty_count = ref 0 in
  let object_count = ref 0 in
  let rec visit depth path value =
    if depth>32 then reject path "manifest list nesting exceeds 32";
    let fields = object_fields path value in
    let kind = string_field path "kind" fields in
    let api = string_field path "apiVersion" fields in
    if kind="List" || kind="CustomResourceDefinitionList" then begin
      require_equal (path ^ ".apiVersion") api
        (if kind="List" then "v1" else "apiextensions.k8s.io/v1");
      (match List.assoc_opt "metadata" fields with
       | None -> ()
       | Some value ->
         let metadata = object_fields (path ^ ".metadata") value in
         if optional_string path "continue" metadata<>"" then reject path "paginated list is incomplete";
         (match List.assoc_opt "remainingItemCount" metadata with
          | None | Some `Null | Some (`Number "0") -> ()
          | Some _ -> reject path "remainingItemCount must be absent, null or zero"));
      arr (path ^ ".items") (field path "items" fields)
      |> List.iteri (fun i -> visit (depth+1) (Printf.sprintf "%s.items[%d]" path i))
    end else begin
      if List.mem_assoc "items" fields || String.ends_with ~suffix:"List" kind then
        reject path "unsupported List wrapper; cannot establish selected CRDs";
      incr object_count;
      if kind="CustomResourceDefinition" then accepted := crd path value :: !accepted
      else if crd_only then excluded := `O ["source_path",`String path;"api_version",`String api;
        "kind",`String kind;"parsed_object_sha256",`String (Soundcheck_core.Sha256.string (json value))] :: !excluded
      else reject path "non-CRD object; use --crd-only for explicit selection"
    end in
  List.iteri (fun i -> function
    | None -> incr empty_count
    | Some value -> visit 0 (Printf.sprintf "documents[%d]" i) value) documents;
  let accepted = List.rev !accepted and excluded = List.rev !excluded in
  if accepted=[] then reject "catalogue" "no CRDs selected";
  let catalogue = (Catalogue.parse "catalogue" (`A (List.map fst accepted)) |> Catalogue.json |> json) ^ "\n" in
  let receipt = json (`O ["schema_version",number 1;"kind",`String "rbac-catalogue-preparation";
    "input_format",`String (Manifest_input.format_name format);"crd_only",`Bool crd_only;
    "source_sha256",`String (Soundcheck_core.Sha256.string source);
    "catalogue_sha256",`String (Soundcheck_core.Sha256.string catalogue);
    "document_count",number (List.length documents);"empty_document_count",number !empty_count;
    "input_object_count",number !object_count;"selected_crds",`A (List.map snd accepted);
    "excluded_objects",`A excluded;"verification_performed",`Bool false;
    "requirements_inferred",`Bool false;"crd_schema_validated",`Bool false;
    "cluster_completeness_established",`Bool false;
    "limitations",strings ["Review and freeze the catalogue independently of candidate RBAC.";
      "Only API group, plural, scope and served status/scale availability are projected.";
      "Version-specific scale paths remain in provenance; their schemas and behavior are not validated.";
      "No API discovery, CRD lifecycle, admission, conversion or controller effects are modeled."]]) in
  {catalogue;receipt;object_count=List.length accepted;excluded_count=List.length excluded})
