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

let list_metadata removed value =
  let path = "manifest.metadata" in
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

let receipt_json value =
  let identity digest bytes = `O ["sha256",`String digest;"bytes",`Number (string_of_int bytes)] in
  json (`O ["schema_version",`Number "1";"kind",`String "rbac-snapshot-preparation";
    "target_profile",`String Assurance.profile_id;
    "input",identity value.input_sha256 value.input_bytes;
    "snapshot",identity value.snapshot_sha256 value.snapshot_bytes;
    "object_count",`Number (string_of_int value.object_count);
    "removed_fields",`A (List.map (fun path -> `String path) value.removed_fields);
    "verification_performed",`Bool false;"completeness_established",`Bool false])
