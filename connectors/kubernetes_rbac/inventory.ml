open Input

type source = {
  id : string;
  path : string;
  sha256 : string;
  format : Manifest_input.format;
  namespace : string option;
  rbac_only : bool;
  source_type : string;
  source_version : string option;
}

type t = { snapshot : string; object_count : int; receipt : string }

let text path limit value =
  let value = str path value |> nonempty path in
  if String.length value > limit then reject path "text exceeds length limit";
  unicode_scalars path value (fun c -> if c < 32 || c = 127 then reject path "control characters are unsupported");
  value

let parse_source index value =
  let p = Printf.sprintf "plan.sources[%d]" index in
  let fields = obj p ["id";"path";"sha256";"format";"namespace";"rbac_only";"source_type";"source_version"] value in
  let id = text (p ^ ".id") 63 (field p "id" fields) in
  ignore (namespace (p ^ ".id") id);
  let path = text (p ^ ".path") 4096 (field p "path" fields) in
  let sha256 = string_field p "sha256" fields in
  if String.length sha256 <> 64 || not (String.for_all (function '0'..'9'|'a'..'f' -> true | _ -> false) sha256)
  then reject (p ^ ".sha256") "expected 64 lowercase hexadecimal digits";
  let format = match string_field p "format" fields with
    | "json" -> Manifest_input.Json | "yaml" -> Yaml | _ -> reject (p ^ ".format") "expected json or yaml" in
  let namespace = match List.assoc_opt "namespace" fields with
    | None | Some `Null -> None
    | Some value -> Some (str (p ^ ".namespace") value |> namespace (p ^ ".namespace")) in
  let rbac_only = match List.assoc_opt "rbac_only" fields with
    | None | Some (`Bool false) -> false | Some (`Bool true) -> true
    | Some _ -> reject (p ^ ".rbac_only") "expected boolean" in
  let source_type = string_field p "source_type" fields in
  if not (List.mem source_type ["supplied";"bootstrap-reference"]) then
    reject (p ^ ".source_type") "expected supplied or bootstrap-reference";
  let source_version = match List.assoc_opt "source_version" fields with
    | None | Some `Null -> None
    | Some value -> Some (text (p ^ ".source_version") 128 value) in
  if source_type="bootstrap-reference" && source_version=None then
    reject (p ^ ".source_version") "bootstrap reference requires an explicit declared version";
  {id;path;sha256;format;namespace;rbac_only;source_type;source_version}

let sources plan =
  let fields = obj "plan" ["schema_version";"kind";"sources"] (parse plan) in
  if field "plan" "schema_version" fields <> `Number "1" then reject "plan" "schema_version must be 1";
  require_equal "plan.kind" (string_field "plan" "kind" fields) "kubernetes-rbac-inventory";
  let values = arr "plan.sources" (field "plan" "sources" fields) in
  if values=[] || List.length values > 64 then reject "plan.sources" "expected between 1 and 64 explicit sources";
  let sources = List.mapi parse_source values in
  let seen = Hashtbl.create (List.length sources) in
  List.iter (fun source ->
    if Hashtbl.mem seen source.id then reject "plan.sources" ("duplicate source id " ^ source.id);
    Hashtbl.add seen source.id ()) sources;
  sources

let identity bytes = `O ["sha256",`String (Soundcheck_core.Sha256.string bytes);
  "bytes",`Number (string_of_int (String.length bytes))]

let assemble ~load plan = protect (fun () ->
  (* Validate the entire plan before the first read. Each source is read once;
     the same exact bytes are pinned, parsed and represented in the receipt. *)
  let sources = sources plan and total_bytes = ref 0 in
  let fragments = List.map (fun source ->
    let bytes = load source.path in
    total_bytes := !total_bytes + String.length bytes;
    if !total_bytes > 16 * 1024 * 1024 then reject "inventory" "combined sources exceed 16 MiB";
    if Soundcheck_core.Sha256.string bytes <> source.sha256 then
      reject ("source " ^ source.id) "SHA-256 mismatch; source bytes differ from the explicit plan";
    match Prepare.fragment_of_manifest ~format:source.format ?namespace:source.namespace ~rbac_only:source.rbac_only bytes with
    | Error reason -> reject ("source " ^ source.id) reason
    | Ok value -> value) sources in
  let items = List.concat_map Prepare.fragment_items fragments in
  let origins = List.map2 (fun source fragment ->
    List.map (fun path -> source.id,path) (Prepare.fragment_source_paths fragment)) sources fragments
    |> List.concat |> Array.of_list in
  let snapshot = json (`O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items]) ^ "\n" in
  let missing = match Snapshot.unresolved_references snapshot with
    | Ok values -> values | Error reason -> reject "assembled inventory" reason in
  if missing<>[] then reject "inventory" ("unresolved roleRef:\n" ^ String.concat "\n"
    (List.map (fun (missing : Snapshot.missing_reference) ->
      let source,path = origins.(missing.binding_index) in
      Printf.sprintf "  source %s %s: %s -> %s" source path missing.binding_label missing.role_label) missing));
  (match Snapshot.of_string snapshot with Ok _ -> () | Error reason -> reject "assembled inventory" reason);
  let objects = List.mapi (fun index value ->
    let fields = match value with `O fields -> fields | _ -> assert false in
    let metadata = match List.assoc "metadata" fields with `O fields -> fields | _ -> assert false in
    let source,path = origins.(index) in
    `O ["snapshot_index",`Number (string_of_int index);"source_id",`String source;"source_path",`String path;
      "identity",`O ["kind",List.assoc "kind" fields;"name",List.assoc "name" metadata;
        "namespace",Option.value ~default:(`String "") (List.assoc_opt "namespace" metadata)]]) items in
  let source_entries = List.map2 (fun source fragment ->
    `O ["id",`String source.id;"path",`String source.path;"source_type",`String source.source_type;
      "declared_source_version",(match source.source_version with None -> `Null | Some version -> `String version);
      "normalization",Prepare.fragment_provenance fragment]) sources fragments in
  let assumed = List.filter_map (fun source ->
    if source.source_type="bootstrap-reference" then Some (`String source.id) else None) sources in
  let object_count = List.length items in
  let receipt = json (`O ["schema_version",`Number "1";"kind",`String "rbac-inventory-assembly";
    "target_profile",`String Assurance.profile_id;"plan",identity plan;"sources",`A source_entries;
    "snapshot",identity snapshot;"object_count",`Number (string_of_int object_count);"objects",`A objects;
    "assumed_bootstrap_sources",`A assumed;"verification_performed",`Bool false;
    "source_authenticity_established",`Bool false;"completeness_established",`Bool false]) in
  {snapshot;object_count;receipt})
