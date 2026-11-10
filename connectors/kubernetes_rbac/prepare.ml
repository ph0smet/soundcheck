open Input

type t = {
  snapshot : string;
  input_sha256 : string;
  snapshot_sha256 : string;
  input_bytes : int;
  snapshot_bytes : int;
  object_count : int;
  removed_fields : string list;
}

(* A deliberately bounded RFC3339 subset. Validate dates as well as syntax;
   do not silently erase malformed timestamps that the API could not decode. *)
let timestamp value =
  let length = String.length value in
  let digits offset count =
    if offset + count > length then None else
    let result = ref 0 and valid = ref true in
    for i = offset to offset + count - 1 do
      let c = value.[i] in
      if c < '0' || c > '9' then valid := false
      else result := !result * 10 + Char.code c - Char.code '0'
    done;
    if !valid then Some !result else None in
  if length < 20 || value.[4] <> '-' || value.[7] <> '-'
     || value.[10] <> 'T' || value.[13] <> ':' || value.[16] <> ':' then false
  else match digits 0 4,digits 5 2,digits 8 2,digits 11 2,digits 14 2,digits 17 2 with
    | Some year,Some month,Some day,Some hour,Some minute,Some second ->
      let leap = year mod 4 = 0 && (year mod 100 <> 0 || year mod 400 = 0) in
      let days = match month with
        | 2 -> if leap then 29 else 28
        | 4 | 6 | 9 | 11 -> 30
        | 1 | 3 | 5 | 7 | 8 | 10 | 12 -> 31
        | _ -> 0 in
      let zone = ref 19 in
      let fraction_valid =
        if value.[!zone] <> '.' then true else begin
          incr zone;
          let start = !zone in
          while !zone < length && value.[!zone] >= '0' && value.[!zone] <= '9' do incr zone done;
          let count = !zone - start in count >= 1 && count <= 9
        end in
      let zone_valid =
        if !zone + 1 = length && value.[!zone] = 'Z' then true
        else if !zone + 6 = length && (value.[!zone] = '+' || value.[!zone] = '-')
                && value.[!zone + 3] = ':' then
          (match digits (!zone + 1) 2,digits (!zone + 4) 2 with
           | Some hour,Some minute -> hour < 24 && minute < 60
           | _ -> false)
        else false in
      year >= 1 && day >= 1 && day <= days && hour < 24 && minute < 60
      && second < 60 && fraction_valid && zone_valid
    | _ -> false

let nonnegative_int64 path = function
  | `Number value ->
    (match Int64.of_string_opt value with
     | Some number when number >= 0L -> number
     | _ -> reject path "expected nonnegative int64")
  | _ -> reject path "expected nonnegative int64"

let bookkeeping path key value =
  match key with
  | "uid" | "resourceVersion" | "selfLink" -> ignore (str path value)
  | "generation" -> ignore (nonnegative_int64 path value)
  | "creationTimestamp" ->
    (match value with
     | `Null -> ()
     | `String value when timestamp value -> ()
     | _ -> reject path "expected null or supported RFC3339 timestamp")
  | "generateName" -> require_equal path (str path value) ""
  | "deletionTimestamp" | "deletionGracePeriodSeconds" ->
    if value <> `Null then reject path "active deletion state cannot be prepared"
  | "ownerReferences" | "finalizers" | "managedFields" ->
    (match value with
     | `Null | `A [] -> ()
     | _ -> reject path "only absent, null or empty metadata is supported")
  | _ -> reject path "unsupported bookkeeping field"

let object_metadata removed path value =
  let kept = ["name";"namespace";"labels";"annotations"] in
  let discarded = ["uid";"resourceVersion";"selfLink";"generation";
    "creationTimestamp";"generateName";"deletionTimestamp";
    "deletionGracePeriodSeconds";"ownerReferences";"finalizers";"managedFields"] in
  let fields = obj path (kept @ discarded) value in
  `O (List.filter (fun (key,value) ->
    if List.mem key kept then true else begin
      let path = path ^ "." ^ key in
      bookkeeping path key value;
      removed := path :: !removed;
      false
    end) fields)

let list_metadata ?(path="manifest.metadata") removed value =
  let fields = obj path ["resourceVersion";"selfLink";"continue";"remainingItemCount"] value in
  List.iter (fun (key,value) ->
    let path = path ^ "." ^ key in
    (match key with
     | "resourceVersion" | "selfLink" -> ignore (str path value)
     | "continue" ->
       if str path value <> "" then reject path "unfinished list pagination"
     | "remainingItemCount" ->
       if value <> `Null && nonnegative_int64 path value <> 0L then
         reject path "unfinished list pagination"
     | _ -> assert false);
    removed := path :: !removed) fields;
  `O []

let of_string source = protect (fun () ->
  let fields = obj "manifest" ["apiVersion";"kind";"metadata";"items"] (parse source) in
  require_equal "manifest.apiVersion" (string_field "manifest" "apiVersion" fields) "v1";
  require_equal "manifest.kind" (string_field "manifest" "kind" fields) "List";
  let items = arr "manifest.items" (field "manifest" "items" fields) in
  let removed = ref [] in
  let metadata = match List.assoc_opt "metadata" fields with
    | None -> []
    | Some value -> ["metadata",list_metadata removed value] in
  let items = List.mapi (fun index value ->
    let path = Printf.sprintf "manifest.items[%d]" index in
    let fields = match value with
      | `O fields -> fields
      | _ -> reject path "expected RBAC object" in
    `O (List.map (fun (key,value) ->
      if key = "metadata" then key,object_metadata removed (path ^ ".metadata") value
      else key,value) fields)) items in
  let snapshot = json (`O (["apiVersion",`String "v1";"kind",`String "List"]
    @ metadata @ ["items",`A items])) ^ "\n" in
  (* No unsupported field, object, rule or unresolved reference can disappear
     through preparation. The original verifier's reader remains authoritative. *)
  (match Snapshot.of_string snapshot with
   | Ok _ -> ()
   | Error reason -> reject "prepared snapshot" reason);
  {snapshot;
   input_sha256=Soundcheck_core.Sha256.string source;
   snapshot_sha256=Soundcheck_core.Sha256.string snapshot;
   input_bytes=String.length source;snapshot_bytes=String.length snapshot;
   object_count=List.length items;
   removed_fields=List.sort_uniq String.compare !removed})

let receipt_fields value =
  let identity digest bytes = `O ["sha256",`String digest;"bytes",`Number (string_of_int bytes)] in
  ["schema_version",`Number "1";"kind",`String "rbac-snapshot-preparation";
    "target_profile",`String Assurance.profile_id;
    "input",identity value.input_sha256 value.input_bytes;
    "snapshot",identity value.snapshot_sha256 value.snapshot_bytes;
    "object_count",`Number (string_of_int value.object_count);
    "removed_fields",`A (List.map (fun path -> `String path) value.removed_fields);
    "verification_performed",`Bool false;"completeness_established",`Bool false]

let receipt_json value = json (`O (receipt_fields value))

type manifest = { prepared : t; excluded_count : int; provenance : (string * Strict_json.value) list }
let manifest_snapshot value = value.prepared
let manifest_excluded_count value = value.excluded_count
type fragment = { manifest : manifest; items : Strict_json.value list; source_paths : string list }
let fragment_items value = value.items
let fragment_source_paths value = value.source_paths

let fragment_of_manifest ~format ?namespace:namespace_context ?(rbac_only=false) source = protect (fun () ->
  Option.iter (fun value -> ignore (namespace "namespace context" value)) namespace_context;
  (* Parse every document before projecting anything, including excluded objects. *)
  let documents = Manifest_input.parse format source in
  let removed = ref [] and defaults = ref [] and retained = ref [] in
  let excluded = ref [] and wrappers = ref [] and empty = ref [] in
  let items = ref [] and count = ref 0 in
  let set key value fields =
    if List.mem_assoc key fields then List.map (fun (k,v) -> k,if k=key then value else v) fields
    else fields @ [key,value] in
  let record_default path value =
    defaults := `O ["path",`String path;"value",`String value] :: !defaults in
  let kinds = ["Role";"RoleBinding";"ClusterRole";"ClusterRoleBinding"] in
  let list_kinds = List.map (fun kind -> kind ^ "List") kinds in
  let rec collect path ?inferred value =
    let fields = match value with `O fields -> fields | _ -> reject path "expected Kubernetes object" in
    let fields = match inferred with
      | None -> fields
      | Some kind ->
        let absent key = match List.assoc_opt key fields with
          | None | Some (`String "") -> true
          | Some (`String _) -> false
          | Some _ -> reject (path ^ "." ^ key) "expected string" in
        let missing_kind = absent "kind" and missing_api = absent "apiVersion" in
        if missing_kind && missing_api then begin
          record_default (path ^ ".apiVersion") api_version;
          record_default (path ^ ".kind") kind;
          fields |> set "apiVersion" (`String api_version) |> set "kind" (`String kind)
        end else begin
          require_equal (path ^ ".kind") (string_field path "kind" fields) kind;
          require_equal (path ^ ".apiVersion") (string_field path "apiVersion" fields) api_version;
          fields
        end in
    let kind = string_field path "kind" fields |> nonempty (path ^ ".kind") in
    let api = string_field path "apiVersion" fields |> nonempty (path ^ ".apiVersion") in
    if kind = "List" || List.mem kind list_kinds then begin
      let generic = kind = "List" in
      require_equal (path ^ ".apiVersion") api (if generic then "v1" else api_version);
      ignore (obj path ["apiVersion";"kind";"metadata";"items"] (`O fields));
      Option.iter (fun metadata -> ignore (list_metadata ~path:(path ^ ".metadata") removed metadata))
        (List.assoc_opt "metadata" fields);
      let children = arr (path ^ ".items") (field path "items" fields) in
      wrappers := `O ["path",`String path;"apiVersion",`String api;"kind",`String kind;
        "item_count",`Number (string_of_int (List.length children))] :: !wrappers;
      let inferred = if generic then None else Some (String.sub kind 0 (String.length kind - 4)) in
      List.iteri (fun index child -> collect (Printf.sprintf "%s.items[%d]" path index) ?inferred child) children
    end else if List.mem kind kinds then begin
      require_equal (path ^ ".apiVersion") api api_version;
      let metadata_path = path ^ ".metadata" in
      let metadata = object_metadata removed metadata_path (field path "metadata" fields) in
      let metadata = match metadata,namespace_context with
        | `O fields,Some ns when kind="Role" || kind="RoleBinding" ->
          (match List.assoc_opt "namespace" fields with
           | None | Some (`String "") ->
             record_default (metadata_path ^ ".namespace") ns;
             `O (set "namespace" (`String ns) fields)
           | _ -> metadata)
        | _ -> metadata in
      let value = `O (set "metadata" metadata fields) in
      (* Fragment validation checks all selected objects, including unbound
         roles and duplicates. The final snapshot must also resolve every ref. *)
      retained := `O ["source_path",`String path;"snapshot_index",`Number (string_of_int !count)] :: !retained;
      incr count;
      items := value :: !items
    end else if api = group || String.starts_with ~prefix:(group ^ "/") api then
      reject path "unsupported RBAC kind (cannot exclude an RBAC object)"
    else if String.ends_with ~suffix:"List" kind || List.mem_assoc "items" fields then
      reject path "unsupported List/items wrapper (its contents cannot be excluded)"
    else if not rbac_only then
      reject path "non-RBAC object; use --rbac-only to explicitly select RBAC and record exclusions"
    else excluded := `O ["source_path",`String path;"apiVersion",`String api;"kind",`String kind] :: !excluded
  in
  List.iteri (fun index value ->
    let path = Printf.sprintf "documents[%d]" index in
    match value with None -> empty := `String path :: !empty | Some value -> collect path value) documents;
  if !count = 0 then reject "input" "no RBAC objects selected";
  let snapshot = json (`O ["apiVersion",`String "v1";"kind",`String "List";"items",`A (List.rev !items)]) ^ "\n" in
  (* A fragment may refer to roles in another explicit source. Everything else,
     including unsupported rules and duplicate identities, remains strict. *)
  (match Snapshot.unresolved_references snapshot with Ok _ -> () | Error reason -> reject "prepared snapshot" reason);
  let prepared = {snapshot;input_sha256=Soundcheck_core.Sha256.string source;
    snapshot_sha256=Soundcheck_core.Sha256.string snapshot;
    input_bytes=String.length source;snapshot_bytes=String.length snapshot;
    object_count= !count;removed_fields=List.sort_uniq String.compare !removed} in
  let manifest = {prepared;excluded_count=List.length !excluded;provenance=[
    "input_format",`String (Manifest_input.format_name format);
    "document_count",`Number (string_of_int (List.length documents));
    "selection",`String (if rbac_only then "rbac-only" else "all");
    "namespace_context",(match namespace_context with None -> `Null | Some value -> `String value);
    "empty_documents",`A (List.rev !empty);"list_wrappers",`A (List.rev !wrappers);
    "retained_objects",`A (List.rev !retained);"excluded_objects",`A (List.rev !excluded);
    "defaulted_fields",`A (List.rev !defaults)]} in
  let source_paths = List.rev !retained |> List.map (function
    | `O fields -> (match List.assoc "source_path" fields with `String path -> path | _ -> assert false)
    | _ -> assert false) in
  {manifest;items=List.rev !items;source_paths})

let of_manifest ~format ?namespace ?rbac_only source =
  match fragment_of_manifest ~format ?namespace ?rbac_only source with
  | Error reason -> Error reason
  | Ok fragment ->
    (match Snapshot.of_string fragment.manifest.prepared.snapshot with
     | Error reason -> Error ("prepared snapshot: " ^ reason)
     | Ok _ -> Ok fragment.manifest)

let fragment_provenance value =
  let prepared = value.manifest.prepared in
  `O (["input",`O ["sha256",`String prepared.input_sha256;"bytes",`Number (string_of_int prepared.input_bytes)];
    "object_count",`Number (string_of_int prepared.object_count);
    "removed_fields",`A (List.map (fun path -> `String path) prepared.removed_fields)]
    @ List.map (fun (key,field_value) ->
      if key<>"retained_objects" then key,field_value else
      key,`A (List.mapi (fun index path -> `O ["source_path",`String path;
        "object_index",`Number (string_of_int index)]) value.source_paths)) value.manifest.provenance)

let manifest_receipt_json value =
  let fields = receipt_fields value.prepared in
  json (`O (List.map (fun (key,v) -> key,if key="schema_version" then `Number "2" else v) fields
    @ value.provenance))
