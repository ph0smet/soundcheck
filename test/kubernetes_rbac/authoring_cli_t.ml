module K = Soundcheck_kubernetes_rbac
open K.Input

let checks = ref 0
let check label condition = incr checks; if not condition then failwith ("authoring CLI: " ^ label)
let field name = function `O fields -> List.assoc name fields | _ -> failwith "object expected"
let set key value = function
  | `O fields -> `O ((key,value)::List.remove_assoc key fields)
  | _ -> failwith "object expected"
let strings values = `A (List.map (fun value -> `String value) values)
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

let scope version subject resource =
  ["subject",`String subject;"namespace",`String "apps";"resource",`String resource;
   "names",(if resource="configmaps" then strings ["settings"] else `Null)]
  @ if version=1 then [] else ["verb",`String "get"]

let contract ?(username="app") ?(groups=["z";"a"]) version =
  let clause name kind resource = `O (("name",`String name)::("kind",`String kind)::scope version username resource) in
  let change = `O (scope version username "secrets") in
  `O ["kind",`String "kubernetes-rbac-access";"schema_version",`Number (string_of_int version);
    "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
      "identities",`A [`O ["username",`String "unused";"groups",strings []];
                        `O ["username",`String username;"groups",strings groups]]];
    "clauses",`A [clause "config-required" "must_allow" "configmaps";
                   clause "secrets-forbidden" "must_not_grant" "secrets"];
    "change_scope",`A [change;change]]

(* Independently specified canonical bytes for the simple authored contracts:
   no review renderer or contract canonicalizer is used as this expectation. *)
let canonical version =
  let verb = if version=1 then "" else ",\"verb\":\"get\"" in
  Printf.sprintf
    {|{"schema_version":%d,"kind":"kubernetes-rbac-access","context":{"schema_version":1,"snapshot_complete":true,"identities":[{"username":"app","groups":["a","z"]},{"username":"unused","groups":[]}]},"clauses":[{"name":"config-required","kind":"must_allow","subject":"app","namespace":"apps","resource":"configmaps","names":["settings"]%s},{"name":"secrets-forbidden","kind":"must_not_grant","subject":"app","namespace":"apps","resource":"secrets","names":null%s}],"change_scope":[{"subject":"app","namespace":"apps","resource":"secrets","names":null%s}]}|}
    version verb verb verb

let () =
  if Array.length Sys.argv<>3 then failwith "expected CLI binary and authoring fixture directory";
  let binary = absolute Sys.argv.(1) and corpus = absolute Sys.argv.(2) in
  let root = Filename.temp_file "soundcheck-authoring-cli-" "" in
  Unix.unlink root;Unix.mkdir root 0o700;
  Fun.protect ~finally:(fun () -> cleanup root) (fun () ->
    let local name = Filename.concat root name in
    let bin = local "bin" and elsewhere = local "elsewhere" in
    Unix.mkdir bin 0o700;Unix.mkdir elsewhere 0o700;
    List.iter (fun command ->
      let path = Filename.concat bin command in
      write path ("#!/bin/sh\nprintf 'called' > " ^ Filename.quote (local "invoked") ^ "\nexit 97\n");
      Unix.chmod path 0o700) ["z3";"kubectl";"helm";"kustomize"];
    let env = Array.to_list (Unix.environment ()) |> List.filter (fun value -> not (String.starts_with ~prefix:"PATH=" value)) in
    let env = Array.of_list (("PATH=" ^ bin)::env) in
    let run args =
      let out = local "stdout" and err = local "stderr" in
      let stdout = Unix.openfile out [Unix.O_WRONLY;Unix.O_CREAT;Unix.O_TRUNC] 0o600
      and stderr = Unix.openfile err [Unix.O_WRONLY;Unix.O_CREAT;Unix.O_TRUNC] 0o600 in
      let cwd = Sys.getcwd () in
      let pid = Fun.protect ~finally:(fun () -> Sys.chdir cwd;Unix.close stdout;Unix.close stderr) (fun () ->
        Sys.chdir elsewhere;
        Unix.create_process_env binary (Array.of_list (binary::args)) env Unix.stdin stdout stderr) in
      let _,status = Unix.waitpid [] pid in
      let code = match status with Unix.WEXITED code -> code | _ -> failwith "CLI terminated" in
      code,read out,read err in
    let inputs = ref [] in
    let input name bytes =
      let path = local name in
      write path bytes;Unix.chmod path 0o400;inputs := (path,bytes)::!inputs;path in
    let review path =
      let code,out,err = run ["rbac";"check-contract";path] in
      check "successful structural review exits zero" (code=0);
      check "successful review has no stderr" (err="");
      check "structural result is not a proof" (String.starts_with ~prefix:"RBAC contract parsed (structure only; not a verification result).\n" out);
      check "unchecked semantic obligations explicit" (contains out "Inhabitation, consistency, access and repair preservation have NOT been checked.");
      check "completeness not inferred" (contains out "Snapshot completeness is asserted by the contract, not established here.");
      check "counts not user-study measurements" (contains out "not measured authoring effort");
      check "final API authorization not claimed" (contains out "NoOpinion means no RBAC grant, not final API-server denial.");
      check "review exposes no proof verdict" (not (contains out "\"result\":\"proved\""));
      out in
    List.iter (fun version ->
      let source = " \n" ^ json (contract version) ^ "\n" in
      let path = input (Printf.sprintf "contract v%d.json" version) source in
      let out = review path in
      let profile = match version with
        | 1 -> "kubernetes-rbac-v1.34-get-v3" | 2 -> "kubernetes-rbac-v1.34-read-v3"
        | 3 -> "kubernetes-rbac-v1.34-read-write-v3" | _ -> "kubernetes-rbac-v1.34-scoped-read-write-v3" in
      List.iter (fun part -> check ("review contains " ^ part) (contains out part))
        [Printf.sprintf "Contract schema: %d" version;"Selected profile (information only): " ^ profile;
         "Raw artifact SHA-256: " ^ hash source;"Canonical frozen-contract SHA-256: " ^ hash (canonical version);
         "2 identities; 2 group memberships; 2 clauses (1 must_allow, 1 must_not_grant); 1 normalized approved-change scopes.";
         "\"app\"; groups: [\"a\", \"z\"]";"\"unused\"; groups: []";
         "\"config-required\": RBAC must grant get";"\"secrets-forbidden\": RBAC must not grant get";
         "Approved decision changes (separate from access requirements):";
         "including identities without clauses"];
      let code,again,err = run ["rbac";"check-contract";path] in
      check "review deterministic" (code=0 && again=out && err="")) [1;2;3;4];
    let original = json (contract 4) in
    let path = input "v4.json" original in
    let fixture_path = Filename.concat corpus "contract.json" in
    let fixture_bytes = read fixture_path in
    let fixture = review fixture_path in
    check "runnable authoring fixture is schema four" (contains fixture "Contract schema: 4");
    check "fixture review binds its original bytes" (contains fixture ("Raw artifact SHA-256: " ^ hash fixture_bytes));
    let username = "app\n::notice::forged\027[31m\000suffix" and groups = ["group\twith\nbreak";"\027]0;title\007"] in
    let escaped = review (input "escaped.json" (json (contract ~username ~groups 4))) in
    List.iter (fun value -> check "identity and groups rendered as quoted literals" (contains escaped (Printf.sprintf "%S" value))) (username::groups);
    List.iter (fun byte -> check "no raw control byte reaches review output" (not (String.contains escaped byte))) ['\000';'\027';'\007';'\t'];
    check "embedded newline cannot create an annotation line" (not (contains escaped "\n::notice::forged"));
    let scope = `O (scope 4 "app" "configmaps") in
    let clause name kind = scope |> set "name" (`String name) |> set "kind" (`String kind) in
    let inconsistent = contract 4 |> set "clauses" (`A [clause "required" "must_allow";clause "forbidden" "must_not_grant"])
      |> set "change_scope" (`A []) in
    let reviewed = review (input "inconsistent.json" (json inconsistent)) in
    check "empty change scope explains full modeled preservation" (contains reviewed "None. Preserve every modeled decision for every frozen identity.");
    let empty_scope = scope |> set "verb" (`String "list") |> set "namespace" (`O ["exclude",strings []])
      |> set "names" (`O ["empty",`Bool true]) in
    let empty = contract 4 |> set "clauses" (`A [
        empty_scope |> set "name" (`String "empty-required") |> set "kind" (`String "must_allow");
        clause "safety" "must_not_grant"]) in
    let reviewed = review (input "collection-scope.json" (json empty)) in
    check "empty authorization names are described explicitly" (contains reviewed "empty effective authorization name only");
    let no_output label expected args =
      let code,out,err = run args in
      check (label ^ " exit") (code=expected);
      check (label ^ " no stdout") (out="");
      check (label ^ " diagnostic") (err<>"");err in
    List.iteri (fun index args -> ignore (no_output (Printf.sprintf "unsupported arguments %d" index) 2 (["rbac";"check-contract"] @ args)))
      [[];["--help"];[path;"extra"];[path;"--format";"json"];[path;"--format";"human"];
       [path;"--config";"config.json"];[path;"--contract";path];[path;"--subject";"other"];
       [path;"--groups";"admin"];[path;"--namespace";"other"];[path;"--baseline";"baseline.json"];
       [path;"--receipt";local "receipt.json"];[path;"--evidence-dir";local "evidence"]];
    check "rejected output options create no artifact" (not (Sys.file_exists (local "receipt.json")) && not (Sys.file_exists (local "evidence")));
    let bad_subject = scope |> set "subject" (`String "missing\n::notice::forged") |> set "name" (`String "unknown-subject") |> set "kind" (`String "must_allow") in
    let invalid = input "invalid.json" (json (contract 4 |> set "clauses" (`A [bad_subject;clause "safety" "must_not_grant"]))) in
    let error = no_output "invalid subject" 2 ["rbac";"check-contract";invalid] in
    check "diagnostic identifies exact contract field" (contains error "contract.clauses[0].subject");
    check "diagnostic cannot inject a new annotation line" (not (contains error "\n::notice::forged"));
    List.iter (fun (label,bytes) ->
      let path = input (label ^ ".json") bytes in
      ignore (no_output label 2 ["rbac";"check-contract";path]))
      ["malformed","{";"unknown-version",json (contract 4 |> set "schema_version" (`Number "6"));
       "trailing-document",original ^ "{}"];
    ignore (no_output "missing file" 1 ["rbac";"check-contract";local "missing\n::notice::forged"]);
    ignore (no_output "directory" 1 ["rbac";"check-contract";elsewhere]);
    let link = local "symlink.json" in Unix.symlink path link;
    ignore (no_output "symlink" 1 ["rbac";"check-contract";link]);
    let oversized = local "oversized.json" in write oversized (String.make (16 * 1024 * 1024 + 1) ' ');
    ignore (no_output "oversized file" 1 ["rbac";"check-contract";oversized]);
    let code,out,err = run ["rbac";"verify";local "absent-snapshot.json";"--contract";invalid;"--format";"json"] in
    check "normal verify retains invalid-contract exit four" (code=4 && err="");
    let result = parse out in
    check "normal verify retains report schema ten" (field "schema_version" result=`Number "10");
    check "normal verify retains unknown verdict" (field "result" result=`String "unknown");
    check "invalid contract cannot acquire frozen identity" (field "frozen_spec" result=`Null);
    check "normal verify exposes actionable reason" (contains (str "reason" (field "reason" result)) "contract.clauses[0].subject");
    List.iter (fun (path,bytes) -> check "input bytes unchanged" (read path=bytes)) !inputs;
    check "fixture bytes unchanged" (read fixture_path=fixture_bytes);
    check "no solver or cluster tool invoked on any path" (not (Sys.file_exists (local "invoked"))));
  Printf.printf "RBAC authoring CLI: %d checks passed.\n" !checks
