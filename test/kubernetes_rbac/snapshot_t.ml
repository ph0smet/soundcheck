open Soundcheck_kubernetes_rbac

let checks = ref 0
let check label condition =
  incr checks;
  if not condition then failwith label

let read path =
  let ch = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr ch)
    (fun () -> really_input_string ch (in_channel_length ch))

let supported source = match Snapshot.of_string source with Ok _ -> true | Error _ -> false
let object_ fields = "{" ^ fields ^ "}"
let snapshot item = {|{"apiVersion":"v1","kind":"List","items":[|} ^ item ^ "]}"
let role metadata rules =
  object_ ({|"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":|}
           ^ metadata ^ {|,"rules":|} ^ rules)
let meta extra = {|{"name":"reader","namespace":"frontend"|} ^ extra ^ "}"
let rule = {|[{"verbs":["get"],"apiGroups":[""],"resources":["configmaps"]}]|}

let () =
  let dir = Sys.argv.(1) in
  Array.iter (fun filename ->
      let number = int_of_string (String.sub filename 0 2) in
      let expected = not (List.mem number [17;18;19;20;26;27]) in
      check filename (supported (read (Filename.concat dir filename)) = expected))
    (Sys.readdir dir);
  let valid = snapshot (role (meta "") rule) in
  check "minimal valid snapshot" (supported valid);
  List.iter (fun (label,source) -> check label (not (supported source)))
    ["trailing JSON", valid ^ "{}";
     "trailing YAML", valid ^ "\n---\n{}";
     "duplicate decoded key", {|{"apiVersion":"v1","kind":"List","it\u0065ms":[],"items":[]}|};
     "wrong schema scalar", {|{"apiVersion":1,"kind":"List","items":[]}|};
     "unpaired surrogate", {|{"apiVersion":"v1","kind":"List","items":[],"x":"\ud800"}|};
     "invalid UTF8", valid ^ "\xff";
     "unknown metadata", snapshot (role (meta {|,"x":true|}) rule);
     "invalid label key", snapshot (role (meta {|,"labels":{"bad/key/name":"ok"}|}) rule);
     "invalid label value", snapshot (role (meta {|,"labels":{"ok":"bad value"}|}) rule);
     "invalid annotation key", snapshot (role (meta {|,"annotations":{"/bad":"value"}|}) rule);
     "annotation non-string", snapshot (role (meta {|,"annotations":{"ok":42}|}) rule);
     "duplicate metadata map key", snapshot (role (meta {|,"labels":{"ok":"a","ok":"b"}|}) rule);
     "aggregation", {|{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"reader"},"rules":[],"aggregationRule":null}]}|};
     "nonresource boundary", snapshot (role (meta "") {|[{"verbs":["get"],"apiGroups":[""],"resources":["configmaps"],"nonResourceURLs":[]}]|})];
  check "valid inert metadata"
    (supported (snapshot (role (meta {|,"labels":{"example.com/App":"Demo_1"},"annotations":{"EXAMPLE.COM/Note":"arbitrary\u0000value"}|}) rule)));
  check "empty snapshot supported" (supported {|{"apiVersion":"v1","kind":"List","items":[]}|});
  let nul = read (Filename.concat dir "23-nul-verb-literal.json") in
  (match Snapshot.of_string nul with
   | Error reason -> failwith reason
   | Ok parsed ->
     check "NUL literal is preserved, never get"
       (List.exists (fun (g : Snapshot.bound_grant) ->
           List.exists (fun (r : Snapshot.rule) -> List.mem "get\000suffix" r.verbs) g.bound_rules)
          (Snapshot.grants parsed)));
  check "oversized input" (not (supported (String.make (16 * 1024 * 1024 + 1) ' ')));
  Printf.printf "RBAC snapshot: %d checks passed\n" !checks
