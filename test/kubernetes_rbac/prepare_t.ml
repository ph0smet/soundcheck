open Soundcheck_core
module K = Soundcheck_kubernetes_rbac

let checks = ref 0
let check label value = incr checks; if not value then failwith ("RBAC prepare: " ^ label)
let ok = function Ok value -> value | Error reason -> failwith reason
let read path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel)
    (fun () -> really_input_string channel (in_channel_length channel))
let fields = function `O values -> values | _ -> failwith "expected object"
let field name value = List.assoc name (fields value)
let set name value object_ = `O ((name,value) :: List.remove_assoc name (fields object_))
let array = function `A values -> values | _ -> failwith "expected array"
let rec ordered = function
  | `O values -> `O (List.sort compare (List.map (fun (key,value) -> key,ordered value) values))
  | `A values -> `A (List.map ordered values)
  | value -> value
let stringify = K.Input.json
let parse = K.Input.parse
let metadata = `O ["name",`String "reader";"namespace",`String "frontend";
  "labels",`O ["example.com/App",`String "Demo_1"];
  "annotations",`O ["EXAMPLE.COM/Note",`String "private annotation\000retained"]]
let rules = `A [`O ["verbs",`A [`String "get"];"apiGroups",`A [`String ""];
  "resources",`A [`String "configmaps"]]]
let role = `O ["apiVersion",`String "rbac.authorization.k8s.io/v1";"kind",`String "Role";
  "metadata",metadata;"rules",rules]
let snapshot items = `O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items]
let minimal = snapshot [role]
let object_meta key value = snapshot [set "metadata" (set key value metadata) role]
let list_meta key value = set "metadata" (`O [key,value]) minimal
let supported value = Result.is_ok (K.Prepare.of_string (stringify value))
let inert = [
  "uid",`String "6ae6cb95-3855-4d24-b727-f5e2c108ff51";
  "resourceVersion",`String "opaque/resource/version";
  "selfLink",`String "/apis/rbac.authorization.k8s.io/v1/roles/reader";
  "generation",`Number "42";"creationTimestamp",`String "2026-11-08T09:10:11Z";
  "deletionTimestamp",`Null;"deletionGracePeriodSeconds",`Null;
  "ownerReferences",`A [];"finalizers",`A [];"managedFields",`A [];
  "generateName",`String ""]
let enrich value =
  let items = array (field "items" value) |> List.map (fun item ->
    set "metadata" (`O (fields (field "metadata" item) @ inert)) item) in
  value |> set "items" (`A items) |> set "metadata" (`O [
    "resourceVersion",`String "list-opaque-version";"selfLink",`String "";
    "continue",`String "";"remainingItemCount",`Number "0"])

let () =
  if Array.length Sys.argv <> 2 then failwith "expected RBAC corpus directory";
  let root = Sys.argv.(1) in
  let source = " \n" ^ stringify (enrich minimal) ^ "\n" in
  let prepared = ok (K.Prepare.of_string source) in
  check "input digest binds exact bytes" (prepared.input_sha256 = Sha256.string source);
  check "input size binds exact bytes" (prepared.input_bytes = String.length source);
  check "snapshot digest binds exact bytes" (prepared.snapshot_sha256 = Sha256.string prepared.snapshot);
  check "snapshot size binds exact bytes" (prepared.snapshot_bytes = String.length prepared.snapshot);
  check "snapshot has exactly one terminal newline"
    (String.ends_with ~suffix:"\n" prepared.snapshot && not (String.ends_with ~suffix:"\n\n" prepared.snapshot));
  check "object count includes an unbound role" (prepared.object_count = 1);
  check "prepared snapshot accepted by unchanged strict parser" (Result.is_ok (K.Snapshot.of_string prepared.snapshot));
  check "raw export still rejected by strict parser" (Result.is_error (K.Snapshot.of_string source));
  check "retained metadata and policy bytes decoded without changes"
    (ordered (field "items" (parse prepared.snapshot)) = ordered (field "items" minimal));
  let again = ok (K.Prepare.of_string prepared.snapshot) in
  check "normalization is idempotent" (again.snapshot = prepared.snapshot);
  check "normalization is deterministic" ((ok (K.Prepare.of_string source)).snapshot = prepared.snapshot);
  check "already normalized snapshot removes nothing" (again.removed_fields = []);
  check "every dropped field is counted once" (List.length prepared.removed_fields = List.length inert + 4);
  check "removal paths do not repeat" (List.length (List.sort_uniq compare prepared.removed_fields)
    = List.length prepared.removed_fields);
  let expected_paths =
    List.map (fun (key,_) -> "manifest.items[0].metadata." ^ key) inert @
    List.map (fun key -> "manifest.metadata." ^ key)
      ["resourceVersion";"selfLink";"continue";"remainingItemCount"] |> List.sort compare in
  check "receipt names every removed field in stable order" (prepared.removed_fields = expected_paths);
  let receipt = K.Prepare.receipt_json prepared in
  let receipt_value = parse receipt in
  check "receipt serialization does not add a newline" (not (String.ends_with ~suffix:"\n" receipt));
  check "receipt schema and target"
    (field "schema_version" receipt_value = `Number "1" &&
     field "kind" receipt_value = `String "rbac-snapshot-preparation" &&
     field "target_profile" receipt_value = `String K.Assurance.profile_id);
  check "receipt is not a verification or completeness claim"
    (field "verification_performed" receipt_value = `Bool false &&
     field "completeness_established" receipt_value = `Bool false);
  List.iter (fun (key,digest,bytes) ->
    let value = field key receipt_value in
    check ("receipt " ^ key ^ " exact digest and bytes")
      (field "sha256" value = `String digest && field "bytes" value = `Number (string_of_int bytes)))
    ["input",prepared.input_sha256,prepared.input_bytes;
     "snapshot",prepared.snapshot_sha256,prepared.snapshot_bytes];
  check "receipt object count" (field "object_count" receipt_value = `Number "1");
  check "receipt removal paths" (field "removed_fields" receipt_value = `A (List.map (fun s -> `String s) expected_paths));
  check "receipt exposes only preparation accounting"
    (List.sort compare (List.map fst (fields receipt_value)) = List.sort compare
      ["schema_version";"kind";"target_profile";"input";"snapshot";"object_count";
       "removed_fields";"verification_performed";"completeness_established"]);
  check "empty snapshot remains empty, not a proof"
    ((ok (K.Prepare.of_string (stringify (snapshot [])))).object_count = 0);
  List.iter (fun (key,value) -> check ("allowed object metadata: " ^ key) (supported (object_meta key value)))
    (inert @ ["uid",`String "";"resourceVersion",`String "";"selfLink",`String "";
      "generation",`Number "0";"generation",`Number "9223372036854775807";
      "creationTimestamp",`Null;"creationTimestamp",`String "2024-02-29T23:59:59Z";
      "creationTimestamp",`String "2000-02-29T00:00:00Z";
      "creationTimestamp",`String "0001-01-01T00:00:00Z";
      "creationTimestamp",`String "9999-12-31T23:59:59Z";
      "creationTimestamp",`String "2026-11-08T09:10:11.1Z";
      "creationTimestamp",`String "2026-11-08T09:10:11.123456789+05:30";
      "creationTimestamp",`String "2026-11-08T09:10:11-00:00";
      "creationTimestamp",`String "2026-11-08T09:10:11+23:59";
      "ownerReferences",`Null;"finalizers",`Null;"managedFields",`Null]);
  List.iter (fun (key,value) -> check ("allowed list metadata: " ^ key) (supported (list_meta key value)))
    ["resourceVersion",`String "";"resourceVersion",`String "opaque-17";
     "selfLink",`String "/apis/rbac.authorization.k8s.io/v1/roles";
     "continue",`String "";"remainingItemCount",`Null;"remainingItemCount",`Number "0"];
  List.iteri (fun i (key,value) ->
    check (Printf.sprintf "invalid object metadata %d (%s)" i key) (not (supported (object_meta key value))))
    ["uid",`Null;"uid",`Number "3";"resourceVersion",`Bool false;"selfLink",`O [];
     "generation",`Number "-1";"generation",`Number "9223372036854775808";
     "generation",`Number "1.0";"generation",`Number "1e0";"generation",`String "1";"generation",`Null;
     "creationTimestamp",`Number "0";"creationTimestamp",`String "";
     "creationTimestamp",`String "2023-02-29T00:00:00Z";
     "creationTimestamp",`String "1900-02-29T00:00:00Z";
     "creationTimestamp",`String "2026-04-31T00:00:00Z";
     "creationTimestamp",`String "2026-11-08T24:00:00Z";
     "creationTimestamp",`String "2026-11-08T00:60:00Z";
     "creationTimestamp",`String "2026-11-08T00:00:60Z";
     "creationTimestamp",`String "0000-01-01T00:00:00Z";
     "creationTimestamp",`String "10000-01-01T00:00:00Z";
     "creationTimestamp",`String "2026-00-08T00:00:00Z";
     "creationTimestamp",`String "2026-13-08T00:00:00Z";
     "creationTimestamp",`String "2026-11-00T00:00:00Z";
     "creationTimestamp",`String "2026-11-08 00:00:00Z";
     "creationTimestamp",`String "2026-11-08T00:00:00z";
     "creationTimestamp",`String "2026-11-08T00:00:00";
     "creationTimestamp",`String "2026-11-08T00:00:00,1Z";
     "creationTimestamp",`String "2026-11-08T00:00:00.Z";
     "creationTimestamp",`String "2026-11-08T00:00:00.1234567890Z";
     "creationTimestamp",`String "2026-11-08T00:00:00+24:00";
     "creationTimestamp",`String "2026-11-08T00:00:00+00:60";
     "creationTimestamp",`String "2026-11-08";
     "deletionTimestamp",`String "2026-11-08T09:10:11Z";
     "deletionTimestamp",`String "";"deletionGracePeriodSeconds",`Number "0";
     "deletionGracePeriodSeconds",`Number "30";"deletionGracePeriodSeconds",`Bool false;
     "ownerReferences",`A [`O ["apiVersion",`String "v1";"kind",`String "ConfigMap";
       "name",`String "owner";"uid",`String "owner-uid"]];
     "ownerReferences",`O [];"finalizers",`A [`String "example.com/cleanup"];
     "finalizers",`String "";
     "managedFields",`A [`O ["manager",`String "kubectl";"operation",`String "Update";
       "apiVersion",`String "rbac.authorization.k8s.io/v1";"fieldsType",`String "FieldsV1";"fieldsV1",`O []]];
     "managedFields",`O [];"generateName",`String "reader-";"generateName",`Null;
     "futureField",`Null;"clusterName",`String "";
     "labels",`O ["bad/key/name",`String "x"];
     "annotations",`O ["ok",`Number "1"]];
  List.iteri (fun i (key,value) ->
    check (Printf.sprintf "pagination or invalid list metadata %d (%s)" i key)
      (not (supported (list_meta key value))))
    ["continue",`String "next-page";"continue",`Null;"continue",`Number "0";
     "remainingItemCount",`Number "1";"remainingItemCount",`Number "-1";
     "remainingItemCount",`Number "0.0";"remainingItemCount",`String "0";
     "remainingItemCount",`Number "9223372036854775808";
     "resourceVersion",`Number "1";"selfLink",`Null;"creationTimestamp",`Null;"unknown",`Null];
  List.iter (fun (label,value) -> check label (not (supported value)))
    ["individual object is not a complete List",role;
     "typed List requires separate support",set "kind" (`String "RoleList") minimal;
     "non-core List apiVersion",set "apiVersion" (`String "rbac.authorization.k8s.io/v1") minimal;
     "array of objects is not List",`A [role];
     "nested List rejected",snapshot [minimal];
     "null list metadata rejected",set "metadata" `Null minimal;
     "unknown root field rejected",set "status" `Null minimal;
     "null items rejected",set "items" `Null minimal;
     "unknown item field cannot be dropped",snapshot [set "status" `Null role];
     "duplicate object identity cannot be deduplicated",snapshot [role;role];
     "namespace cannot be invented",snapshot [set "metadata" (`O ["name",`String "reader"]) role];
     "invalid aggregation cannot be stripped",snapshot [set "aggregationRule" (`O [])
       (role |> set "kind" (`String "ClusterRole") |> set "metadata" (`O ["name",`String "reader"]))];
     "invalid mixed-domain rules cannot be stripped",snapshot [set "rules"
       (`A [set "nonResourceURLs" (`A [`String "/version"]) (List.hd (array rules))]) role]];
  List.iter (fun (label,source) -> check label (Result.is_error (K.Prepare.of_string source)))
    ["trailing JSON",stringify minimal ^ "{}";
     "trailing YAML",stringify minimal ^ "\n---\n{}";
     "YAML input rejected","apiVersion: v1\nkind: List\nitems: []\n";
     "duplicate decoded key",{|{"apiVersion":"v1","kind":"List","items":[],"it\u0065ms":[]}|};
     "duplicate removed metadata key",{|{"apiVersion":"v1","kind":"List","metadata":{"resourceVersion":"a","resourceVersion":"b"},"items":[]}|};
     "invalid UTF8",stringify minimal ^ "\xff";
     "unpaired surrogate",{|{"apiVersion":"v1","kind":"List","items":[],"metadata":{"resourceVersion":"\ud800"}}|};
     "oversized input",String.make (16 * 1024 * 1024 + 1) ' '];
  let spec = ok (K.Contract_spec.of_string (read (root ^ "/contracts/frontend-access.json"))) in
  let requests = ok (K.Evaluate.requests spec (read (root ^ "/requests.json"))) in
  Array.iter (fun filename ->
    if Filename.check_suffix filename ".json" then begin
      let source = read (root ^ "/fixtures/" ^ filename) in
      match K.Snapshot.of_string source with
      | Error _ -> check (filename ^ " remains unsupported") (Result.is_error (K.Prepare.of_string source))
      | Ok original ->
        let value = parse source in
        let enriched = stringify (enrich value) in
        let prepared = ok (K.Prepare.of_string enriched) in
        let normalized = ok (K.Snapshot.of_string prepared.snapshot) in
        check (filename ^ " no object or retained field filtered")
          (ordered (field "items" (parse prepared.snapshot)) = ordered (field "items" value));
        check (filename ^ " object count") (prepared.object_count = List.length (array (field "items" value)));
        check (filename ^ " exact grants unchanged") (K.Snapshot.grants normalized = K.Snapshot.grants original);
        check (filename ^ " concrete request decisions unchanged")
          (K.Evaluate.decisions (K.Lower.policy spec normalized) requests =
           K.Evaluate.decisions (K.Lower.policy spec original) requests)
    end) (Sys.readdir (root ^ "/fixtures"));
  Printf.printf "RBAC prepare: %d checks passed (no solver)\n" !checks
