module K = Soundcheck_kubernetes_rbac
open K.Input

let checks = ref 0
let check label condition = incr checks; if not condition then failwith ("aggregation CLI: " ^ label)
let field name = function `O fields -> List.assoc name fields | _ -> failwith "object expected"
let array = function `A values -> values | _ -> failwith "array expected"
let strings values = `A (List.map (fun value -> `String value) values)
let rec normalize = function
  | `O fields -> `O (List.map (fun (k,v) -> k,normalize v) fields |> List.sort compare)
  | `A values -> `A (List.map normalize values)
  | value -> value
let read path = let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () -> really_input_string channel (in_channel_length channel))
let write path bytes = let channel = open_out_bin path in
  Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () -> output_string channel bytes)
let rec cleanup path = match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR -> Array.iter (fun name -> cleanup (Filename.concat path name)) (Sys.readdir path);Unix.rmdir path
  | _ -> Unix.unlink path
let contains text part =
  let rec loop i = i+String.length part <= String.length text &&
    (String.sub text i (String.length part)=part || loop (i+1)) in loop 0
let absolute path = if Filename.is_relative path then Filename.concat (Sys.getcwd ()) path else path
let hash = Soundcheck_core.Sha256.string
let list items = `O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items]
let role ?aggregation ?(selected="yes") name rules = `O (
  ["apiVersion",`String api_version;"kind",`String "ClusterRole";
   "metadata",`O ["name",`String name;"labels",`O ["selected",`String selected]];"rules",`A rules]
  @ match aggregation with None -> [] | Some value -> ["aggregationRule",value])
let config = `O ["verbs",strings ["get"];"apiGroups",strings [""];"resources",strings ["configmaps"];
  "resourceNames",strings ["settings"]]
let secret = `O ["verbs",strings ["get"];"apiGroups",strings [""];"resources",strings ["secrets"]]
let aggregation = `O ["clusterRoleSelectors",`A [`O ["matchLabels",`O ["selected",`String "yes"]]]]
let aggregate rules = role ~aggregation ~selected:"no" "aggregate" rules
let binding = `O ["apiVersion",`String api_version;"kind",`String "RoleBinding";
  "metadata",`O ["name",`String "reader";"namespace",`String "apps"];
  "subjects",`A [`O ["kind",`String "User";"apiGroup",`String group;"name",`String "alice"]];
  "roleRef",`O ["apiGroup",`String group;"kind",`String "ClusterRole";"name",`String "aggregate"]]
let safe_items = [aggregate [config];role "config" [config];role ~selected:"no" "secret" [secret];binding]
let unsafe_items = [aggregate [config;secret];role "config" [config];role "secret" [secret];binding]
let stale_items = [aggregate [config];role "config" [config];role "secret" [secret];binding]
let denied_items = [aggregate [];role ~selected:"no" "config" [config];role ~selected:"no" "secret" [secret];binding]

(* Frozen expected canonical bytes are independent of the implementation's
   canonicalizer and remain identical across aggregation profile revisions. *)
let canonical version =
  let verb = if version=1 then "" else ",\"verb\":\"get\"" in
  Printf.sprintf
    {|{"schema_version":%d,"kind":"kubernetes-rbac-access","context":{"schema_version":1,"snapshot_complete":true,"identities":[{"username":"alice","groups":[]}]},"clauses":[{"name":"config-required","kind":"must_allow","subject":"alice","namespace":"apps","resource":"configmaps","names":["settings"]%s},{"name":"secrets-forbidden","kind":"must_not_grant","subject":"alice","namespace":"apps","resource":"secrets","names":null%s}],"change_scope":[{"subject":"alice","namespace":"apps","resource":"secrets","names":null%s}]}|}
    version verb verb verb
let profile = function
  | 1 -> "kubernetes-rbac-v1.34-get-v3" | 2 -> "kubernetes-rbac-v1.34-read-v3"
  | 3 -> "kubernetes-rbac-v1.34-read-write-v3" | _ -> "kubernetes-rbac-v1.34-scoped-read-write-v3"

let () =
  if Array.length Sys.argv<>2 then failwith "expected CLI binary";
  let binary = absolute Sys.argv.(1) in
  let root = Filename.temp_file "soundcheck-aggregation-cli-" "" in
  Unix.unlink root;Unix.mkdir root 0o700;
  Fun.protect ~finally:(fun () -> cleanup root) (fun () ->
    let local name = Filename.concat root name in
    let bin = local "bin" and elsewhere = local "elsewhere" in
    Unix.mkdir bin 0o700;Unix.mkdir elsewhere 0o700;
    List.iter (fun command ->
      let path = Filename.concat bin command in
      write path ("#!/bin/sh\nprintf 'called' > " ^ Filename.quote (local "invoked") ^ "\nexit 97\n");
      Unix.chmod path 0o700) ["z3";"kubectl";"helm";"kustomize"];
    let original_env = Unix.environment () in
    let offline_env = Array.to_list original_env |> List.filter (fun value -> not (String.starts_with ~prefix:"PATH=" value)) in
    let offline_env = Array.of_list (("PATH=" ^ bin)::offline_env) in
    let run ?(offline=false) args =
      let out = local "stdout" and err = local "stderr" in
      let stdout = Unix.openfile out [Unix.O_WRONLY;Unix.O_CREAT;Unix.O_TRUNC] 0o600
      and stderr = Unix.openfile err [Unix.O_WRONLY;Unix.O_CREAT;Unix.O_TRUNC] 0o600 in
      let cwd = Sys.getcwd () in
      let pid = Fun.protect ~finally:(fun () -> Sys.chdir cwd;Unix.close stdout;Unix.close stderr) (fun () ->
        Sys.chdir elsewhere;
        Unix.create_process_env binary (Array.of_list (binary::args))
          (if offline then offline_env else original_env) Unix.stdin stdout stderr) in
      let _,status = Unix.waitpid [] pid in
      let code = match status with Unix.WEXITED code -> code | _ -> failwith "CLI terminated" in
      code,read out,read err in
    let inputs = ref [] in
    let input name bytes = let path = local name in
      write path bytes;Unix.chmod path 0o400;inputs := (path,bytes)::!inputs;path in
    let safe = input "safe.json" (json (list safe_items))
    and unsafe = input "unsafe.json" (json (list unsafe_items))
    and stale = input "stale.json" (json (list stale_items))
    and denied = input "deny-all.json" (json (list denied_items)) in
    List.iter (fun version ->
      let frozen = canonical version in
      let contract = input (Printf.sprintf "contract-%d.json" version) (" \n" ^ frozen ^ "\n") in
      let invoke ?(offline=false) command code_expected verdict_expected =
        let code,out,err = run ~offline (["rbac"] @ command @ ["--contract";contract;"--format";"json"]) in
        check "verification exit matches verdict" (code=code_expected);
        check "verification JSON has no stderr" (err="");
        let report = parse out in
        check "unchanged report schema" (field "schema_version" report=`Number "10");
        check "expected verification verdict" (field "result" report=`String verdict_expected);
        check "profile revision identifies aggregate boundary" (field "profile" (field "assurance" report)=`String (profile version));
        check "original contract identity is retained" (field "canonical" (field "frozen_spec" report)=`String frozen);
        check "original contract schema is retained" (field "schema_version" (field "frozen_spec" report)=`Number (string_of_int version));
        report in
      let proved = invoke ["verify";safe] 0 "proved" in
      check "proved within supported profile" (field "status" (field "assurance" proved)=`String "within_profile");
      let violated = invoke ["verify";unsafe] 3 "violated" in
      check "unsafe aggregate fails original safety clause" (field "name" (field "clause" violated)=`String "secrets-forbidden");
      let witness = field "counterexample" violated in
      check "witness names original materialized aggregate slot" (field "granting_rules" witness=
        `A [`String "RoleBinding/apps/reader -> ClusterRole/aggregate/rules/1"]);
      check "witness is a secret request" (field "resource_kind" (field "object_request" witness)=`String "secrets");
      let removed = invoke ["verify";denied] 3 "violated" in
      check "consistent deny-all still fails required access" (field "name" (field "clause" removed)=`String "config-required");
      let compared = invoke ["compare";unsafe;safe] 0 "proved" in
      check "repair comparison uses frozen allowed change scope" (field "property" compared=`String "rbac-repair-preservation");
      List.iter (fun command ->
        let unknown = invoke ~offline:true command 4 "unknown" in
        check "stale aggregate cannot obtain assurance" (field "status" (field "assurance" unknown)=`String "unsupported");
        check "stale aggregate has no counterexample" (field "counterexample" unknown=`Null);
        check "stale aggregate has an input diagnostic" (contains (str "reason" (field "reason" unknown)) "aggregation"))
        [["verify";stale];["compare";safe;stale];["compare";stale;safe]];
      let code,review,err = run ~offline:true ["rbac";"check-contract";contract] in
      check "contract-only review remains offline" (code=0 && err="" && contains review "structure only; not a verification result");
      check "review reports revised profile" (contains review (profile version));
      check "review retains frozen canonical identity" (contains review (hash frozen));
      let code,_,_ = run ~offline:true ["rbac";"verify";safe;"--contract";contract;"--aggregation-mode";"ignore"] in
      check "candidate cannot override aggregate semantics" (code=2)) [1;2;3;4];
    List.iter (fun options ->
      let receipt_path = local (if options=[] then "prepare-legacy.json" else "prepare-manifest.json") in
      let code,out,err = run ~offline:true (["rbac";"prepare";safe] @ options @ ["--receipt";receipt_path]) in
      check "preparation accepts consistent aggregate" (code=0);
      check "preparation retains exact policy fields" (normalize (parse out)=normalize (parse (read safe)));
      check "preparation does not claim live convergence" (contains err "No verification or completeness claim");
      let receipt = parse (read receipt_path) in
      check "receipt binds emitted complete policy" (field "sha256" (field "snapshot" receipt)=`String (hash out));
      check "preparation is not verification" (field "verification_performed" receipt=`Bool false);
      let refused = local (if options=[] then "stale-legacy.json" else "stale-manifest.json") in
      let code,out,err = run ~offline:true (["rbac";"prepare";stale] @ options @ ["--receipt";refused]) in
      check "stale preparation fails without output" (code=2 && out="" && err<>"");
      check "stale preparation does not create receipt" (not (Sys.file_exists refused))) [[];["--input-format";"json"]];
    let aggregate_source = json (list [aggregate [config];binding])
    and contributor_source = json (list [role "config" [config];role ~selected:"no" "secret" [secret]]) in
    let _ = input "aggregate.json" aggregate_source and _ = input "contributors.json" contributor_source in
    let descriptor id bytes = `O ["id",`String id;"path",`String (id ^ ".json");"format",`String "json";
      "sha256",`String (hash bytes);"source_type",`String "supplied"] in
    let plan = input "plan.json" (json (`O ["schema_version",`Number "1";"kind",`String "kubernetes-rbac-inventory";
      "sources",`A [descriptor "aggregate" aggregate_source;descriptor "contributors" contributor_source]])) in
    let receipt_path = local "inventory-receipt.json" in
    let code,out,err = run ~offline:true ["rbac";"inventory";plan;"--receipt";receipt_path] in
    check "cross-source aggregate assembly succeeds from other cwd" (code=0);
    check "all aggregate, contributor and binding objects remain" (List.length (array (field "items" (parse out)))=4);
    check "assembly output passes strict complete snapshot reader" (Result.is_ok (K.Snapshot.of_string out));
    check "assembly does not infer completeness" (contains err "No verification or completeness claim");
    let receipt = parse (read receipt_path) in
    check "inventory receipt schema unchanged" (field "schema_version" receipt=`Number "1");
    check "inventory receipt identifies revised profile" (field "target_profile" receipt=`String (profile 1));
    check "inventory receipt retains false completeness claim" (field "completeness_established" receipt=`Bool false);
    check "no solver or cluster tool needed for offline/rejection paths" (not (Sys.file_exists (local "invoked")));
    List.iter (fun (path,bytes) -> check "every input byte remains unchanged" (read path=bytes)) !inputs);
  Printf.printf "RBAC aggregate CLI: %d checks passed.\n" !checks
