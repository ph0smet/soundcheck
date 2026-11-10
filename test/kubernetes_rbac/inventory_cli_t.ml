module K = Soundcheck_kubernetes_rbac
open K.Input

let checks = ref 0
let check label condition = incr checks; if not condition then failwith ("inventory CLI: " ^ label)
let field name = function `O fields -> List.assoc name fields | _ -> failwith "object expected"
let array = function `A values -> values | _ -> failwith "array expected"
let read path = let c = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr c) (fun () -> really_input_string c (in_channel_length c))
let write path bytes = let c = open_out_bin path in
  Fun.protect ~finally:(fun () -> close_out_noerr c) (fun () -> output_string c bytes)
let rec cleanup path = match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR -> Array.iter (fun name -> cleanup (Filename.concat path name)) (Sys.readdir path); Unix.rmdir path
  | _ -> Unix.unlink path
let contains text part =
  let rec loop i = i+String.length part <= String.length text &&
    (String.sub text i (String.length part)=part || loop (i+1)) in loop 0
let absolute path = if Filename.is_relative path then Filename.concat (Sys.getcwd ()) path else path
let list items = `O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items]
let descriptor id path bytes = `O ["id",`String id;"path",`String path;"format",`String "json";
  "sha256",`String (Soundcheck_core.Sha256.string bytes);"source_type",`String "supplied"]
let plan sources = json (`O ["schema_version",`Number "1";"kind",`String "kubernetes-rbac-inventory";"sources",`A sources])

let () =
  if Array.length Sys.argv<>3 then failwith "expected CLI and RBAC corpus";
  let binary = absolute Sys.argv.(1) and corpus = absolute Sys.argv.(2) in
  let root = Filename.temp_file "soundcheck-inventory-cli-" "" in
  Unix.unlink root;Unix.mkdir root 0o700;
  Fun.protect ~finally:(fun () -> cleanup root) (fun () ->
    let local name = Filename.concat root name in
    let bin = local "bin" and sources = local "sources" and elsewhere = local "elsewhere" in
    List.iter (fun dir -> Unix.mkdir dir 0o700) [bin;sources;elsewhere];
    (* No external process belongs in these workflows. Traps distinguish this
       from merely succeeding when z3/kubectl cannot be found. *)
    List.iter (fun command -> let path = Filename.concat bin command in
      write path ("#!/bin/sh\nprintf 'called' > " ^ Filename.quote (local "invoked") ^ "\nexit 97\n");
      Unix.chmod path 0o700) ["z3";"kubectl";"helm";"kustomize"];
    let env = Array.to_list (Unix.environment ()) |> List.filter (fun s -> not (String.starts_with ~prefix:"PATH=" s)) in
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
    let fixture = read (corpus ^ "/fixtures/03-valid-repair.json") |> parse |> field "items" |> array in
    let roles,bindings = List.partition (fun item -> List.mem (field "kind" item) [`String "Role";`String "ClusterRole"]) fixture in
    let role_bytes = json (list roles) and binding_bytes = json (list bindings) in
    let role_path = Filename.concat sources "roles with spaces.json"
    and binding_path = Filename.concat sources "bindings.json" and plan_path = Filename.concat sources "plan.json" in
    write role_path role_bytes; write binding_path binding_bytes;
    let descriptors = [descriptor "bindings" "bindings.json" binding_bytes;
      descriptor "roles" "roles with spaces.json" role_bytes] in
    let original_plan = plan descriptors in
    write plan_path original_plan;
    let receipt_path = local "receipt.json" in
    let old_umask = Unix.umask 0 in
    let code,stdout,stderr = Fun.protect ~finally:(fun () -> ignore (Unix.umask old_umask)) (fun () ->
      run ["rbac";"inventory";plan_path;"--receipt";receipt_path]) in
    check "relative source paths use plan directory, not cwd" (code=0);
    check "snapshot remains strictly parseable" (Result.is_ok (K.Snapshot.of_string stdout));
    check "every role and binding retained" (List.length (array (field "items" (parse stdout)))=List.length fixture);
    check "workflow summary on stderr" (contains stderr "No verification or completeness claim");
    check "private receipt with permissive umask" ((Unix.stat receipt_path).Unix.st_perm land 0o777=0o600);
    let receipt_bytes = read receipt_path and receipt = read receipt_path |> parse in
    check "receipt binds exact output" (field "sha256" (field "snapshot" receipt)=`String (Soundcheck_core.Sha256.string stdout));
    check "receipt binds exact plan" (field "sha256" (field "plan" receipt)=`String (Soundcheck_core.Sha256.string original_plan));
    let code,repeated,_ = run ["rbac";"inventory";plan_path] in
    check "receipt optional, output deterministic" (code=0 && repeated=stdout);
    let snapshot_path = local "snapshot.json" in write snapshot_path stdout;
    let contract = corpus ^ "/contracts/frontend-access.json" in
    let code,inspection,stderr = run ["rbac";"inspect";snapshot_path;"--contract";contract] in
    check "inspection is offline JSON" (code=0 && stderr="");
    let inspection = parse inspection in
    check "exact frozen context" (List.length (array (field "identities" inspection))=5);
    check "raw contract hash bound" (field "sha256" (field "contract" inspection)=`String (Soundcheck_core.Sha256.string (read contract)));
    check "no authorization implied" (field "authorization_evaluated" inspection=`Bool false);
    check "external tools never invoked" (not (Sys.file_exists (local "invoked")));
    let no_output label expected args =
      let code,out,err = run args in
      check (label ^ " exit") (code=expected);
      check (label ^ " no stdout") (out="");
      check (label ^ " diagnostic") (err<>"") in
    no_output "existing receipt" 1 ["rbac";"inventory";plan_path;"--receipt";receipt_path];
    check "existing receipt unchanged" (read receipt_path=receipt_bytes);
    no_output "receipt collides with plan" 1 ["rbac";"inventory";plan_path;"--receipt";plan_path];
    no_output "receipt collides with source" 1 ["rbac";"inventory";plan_path;"--receipt";role_path];
    check "all inputs unchanged" (read plan_path=original_plan && read role_path=role_bytes && read binding_path=binding_bytes);
    no_output "unwritable receipt" 1 ["rbac";"inventory";plan_path;"--receipt";local "missing/receipt.json"];
    List.iter (fun flags -> no_output "unapproved inventory override" 2 (["rbac";"inventory";plan_path] @ flags))
      [["--namespace";"other"];["--rbac-only"];["--bootstrap";"v1.34.0"];["--format";"json"];
       ["--receipt";local "unused";"--receipt";local "unused2"]];
    List.iter (fun args -> no_output "invalid inspection arguments" 2 (["rbac";"inspect"] @ args))
      [[snapshot_path];[snapshot_path;"--contract";contract;"--groups";"admin"];
       [snapshot_path;"--contract";contract;"--format";"json"]];
    check "invalid flags never write receipt" (not (Sys.file_exists (local "unused")));
    let new_receipt = local "invalid-receipt.json" in
    write role_path (role_bytes ^ "\n");
    no_output "pin mismatch" 2 ["rbac";"inventory";plan_path;"--receipt";new_receipt];
    check "bad pin produces no receipt" (not (Sys.file_exists new_receipt));
    write role_path role_bytes;
    write plan_path (plan [List.hd descriptors]);
    no_output "incomplete inventory" 2 ["rbac";"inventory";plan_path;"--receipt";new_receipt];
    check "missing refs produce no receipt" (not (Sys.file_exists new_receipt));
    write plan_path original_plan;
    let symlink = local "linked-plan" in Unix.symlink plan_path symlink;
    no_output "symlink plan" 1 ["rbac";"inventory";symlink];
    Unix.unlink role_path;Unix.symlink binding_path role_path;
    no_output "symlink source" 1 ["rbac";"inventory";plan_path];
    Unix.unlink role_path;write role_path role_bytes;
    no_output "directory source" 1 ["rbac";"inventory";sources];
    let bad_contract = local "invalid-contract.json" in write bad_contract "{}";
    no_output "invalid frozen contract" 2 ["rbac";"inspect";snapshot_path;"--contract";bad_contract];
    write snapshot_path binding_bytes;
    no_output "inspect unresolved refs" 2 ["rbac";"inspect";snapshot_path;"--contract";contract];
    no_output "missing file" 1 ["rbac";"inventory";local "missing.json"];
    check "no external execution even on failures" (not (Sys.file_exists (local "invoked"))));
  Printf.printf "RBAC inventory CLI: %d checks passed.\n" !checks
