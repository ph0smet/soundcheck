open Soundcheck_core
module K = Soundcheck_kubernetes_rbac

let checks = ref 0
let check label value = incr checks; if not value then failwith ("RBAC prepare CLI: " ^ label)
let ok = function Ok value -> value | Error reason -> failwith reason
let read path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel)
    (fun () -> really_input_string channel (in_channel_length channel))
let write path bytes =
  let channel = open_out_bin path in
  Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () -> output_string channel bytes)
let field name = function `O values -> List.assoc name values | _ -> failwith "expected object"
let fields = function `O values -> values | _ -> failwith "expected object"
let set name value object_ = `O ((name,value) :: List.remove_assoc name (fields object_))
let array = function `A values -> values | _ -> failwith "expected array"
let parse = K.Input.parse
let contains text part =
  let rec loop i = i + String.length part <= String.length text &&
    (String.sub text i (String.length part) = part || loop (i+1)) in loop 0
let rec cleanup path =
  match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR -> Array.iter (fun name -> cleanup (Filename.concat path name)) (Sys.readdir path);Unix.rmdir path
  | _ -> Unix.unlink path
let run binary args =
  let output = Filename.temp_file "rbac-prepare-out-" "" and error = Filename.temp_file "rbac-prepare-err-" "" in
  Fun.protect ~finally:(fun () -> Unix.unlink output;Unix.unlink error) (fun () ->
    let stdout = Unix.openfile output [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let stderr = Unix.openfile error [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let pid = Unix.create_process binary (Array.of_list (binary::args)) Unix.stdin stdout stderr in
    Unix.close stdout;Unix.close stderr;
    let _,status = Unix.waitpid [] pid in
    let code = match status with Unix.WEXITED code -> code | _ -> failwith "CLI terminated" in
    code,read output,read error)
let enriched source =
  let value = parse source in
  let items = array (field "items" value) |> List.map (fun item ->
    let metadata = field "metadata" item |> set "uid" (`String "private-export-uid")
      |> set "resourceVersion" (`String "opaque-rv")
      |> set "creationTimestamp" (`String "2026-11-08T09:10:11Z") in
    set "metadata" metadata item) in
  value |> set "items" (`A items) |> set "metadata" (`O ["resourceVersion",`String ""])
  |> K.Input.json

let () =
  if Array.length Sys.argv <> 3 then failwith "expected CLI binary and RBAC corpus";
  let binary = Sys.argv.(1) and corpus = Sys.argv.(2) in
  let root = Filename.temp_file "soundcheck-prepare-cli-" "" in
  Unix.unlink root;Unix.mkdir root 0o700;
  Fun.protect ~finally:(fun () -> cleanup root) (fun () ->
    let local name = Filename.concat root name in
    let fixture name = corpus ^ "/fixtures/" ^ name ^ ".json" in
    let contract = corpus ^ "/contracts/frontend-access.json" in
    let input = local "export with space.json" in
    let source = enriched (read (fixture "01-unsafe")) in
    write input source;
    let prepared = ok (K.Prepare.of_string source) in
    let no_output label expected args =
      let code,stdout,stderr = run binary args in
      check (label ^ " exit") (code=expected);
      check (label ^ " publishes no snapshot") (stdout="");
      check (label ^ " explains failure on stderr") (stderr<>"") in
    let receipt = local "receipt with space.json" in
    let old_umask = Unix.umask 0 in
    let code,stdout,stderr = Fun.protect ~finally:(fun () -> ignore (Unix.umask old_umask)) (fun () ->
      run binary ["rbac";"prepare";input;"--receipt";receipt]) in
    check "preparation succeeds even for an unsafe policy" (code=0);
    check "stdout is the exact normalized bytes" (stdout=prepared.snapshot);
    check "stdout contains exactly one terminal newline"
      (String.ends_with ~suffix:"\n" stdout && not (String.ends_with ~suffix:"\n\n" stdout));
    check "stdout is one strict supported snapshot" (Result.is_ok (K.Snapshot.of_string stdout));
    check "summary stays on stderr" (stderr<>"" && not (contains stderr "private-export-uid"));
    check "source file is unchanged" (read input=source);
    let receipt_bytes = read receipt in
    check "receipt is serialized with one newline" (receipt_bytes=K.Prepare.receipt_json prepared ^ "\n");
    check "receipt owner-only mode even with permissive umask" ((Unix.stat receipt).Unix.st_perm land 0o777 = 0o600);
    let receipt_value = parse receipt_bytes in
    check "receipt binds emitted bytes" (field "sha256" (field "snapshot" receipt_value)=`String (Sha256.string stdout));
    check "receipt does not claim verification" (field "verification_performed" receipt_value=`Bool false);
    check "receipt does not claim completeness" (field "completeness_established" receipt_value=`Bool false);
    let code,without_receipt,stderr = run binary ["rbac";"prepare";input] in
    check "receipt is optional" (code=0 && without_receipt=stdout && stderr<>"");
    no_output "existing receipt" 1 ["rbac";"prepare";input;"--receipt";receipt];
    check "existing receipt never overwritten" (read receipt=receipt_bytes);
    no_output "receipt equals source" 1 ["rbac";"prepare";input;"--receipt";input];
    check "receipt/source collision preserves input" (read input=source);
    let target = local "symlink-target" in write target "retained";
    let link = local "receipt-link" in Unix.symlink target link;
    no_output "receipt symlink" 1 ["rbac";"prepare";input;"--receipt";link];
    check "receipt symlink target untouched" (read target="retained" && (Unix.lstat link).Unix.st_kind=Unix.S_LNK);
    let absent_target = local "never-created" in
    let broken = local "receipt-broken-link" in Unix.symlink absent_target broken;
    no_output "dangling receipt symlink" 1 ["rbac";"prepare";input;"--receipt";broken];
    check "dangling receipt target not created" (not (Sys.file_exists absent_target));
    no_output "receipt directory" 1 ["rbac";"prepare";input;"--receipt";root];
    no_output "missing receipt parent" 1 ["rbac";"prepare";input;"--receipt";local "missing/receipt.json"];
    no_output "missing export" 1 ["rbac";"prepare";local "absent.json"];
    no_output "directory export" 1 ["rbac";"prepare";root];
    let oversized = local "oversized.json" in
    write oversized (String.make (16 * 1024 * 1024 + 1) ' ');
    let oversized_receipt = local "oversized-receipt.json" in
    no_output "oversized export" 1 ["rbac";"prepare";oversized;"--receipt";oversized_receipt];
    check "bounded read failure creates no receipt" (not (Sys.file_exists oversized_receipt));
    List.iteri (fun i args -> no_output (Printf.sprintf "invalid arguments %d" i) 2 args)
      [["rbac";"prepare"];["rbac";"prepare";input;"extra"];
       ["rbac";"prepare";input;"--format";"json"];
       ["rbac";"prepare";input;"--contract";contract];
       ["rbac";"prepare";input;"--evidence-dir";local "evidence"];
       ["rbac";"prepare";input;"--receipt"];
       ["rbac";"prepare";input;"--receipt";""];
       ["rbac";"prepare";input;"--receipt";receipt;"--receipt";local "second.json"]];
    let rejected = [
      "partial pagination",source |> parse |> set "metadata" (`O ["continue",`String "next-page"]) |> K.Input.json;
      "deleting grant cannot disappear",
        (let value = parse source in
         let items = array (field "items" value) |> List.map (fun item ->
           if field "kind" item = `String "RoleBinding" then
             set "metadata" (set "deletionTimestamp" (`String "2026-11-08T09:10:11Z") (field "metadata" item)) item
           else item) in
         K.Input.json (set "items" (`A items) value));
      "unsupported aggregation",read (fixture "30-stale-aggregation");
      "missing reference",read (fixture "17-missing-reference");
      "unknown field",read (fixture "19-unknown-field");
      "trailing document",source ^ "{}";
      "YAML","apiVersion: v1\nkind: List\nitems: []\n"] in
    List.iteri (fun i (label,bytes) ->
      let path = local (Printf.sprintf "invalid-%d.json" i) in write path bytes;
      let receipt = local (Printf.sprintf "invalid-%d-receipt.json" i) in
      no_output label 2 ["rbac";"prepare";path;"--receipt";receipt];
      check (label ^ " never creates receipt") (not (Sys.file_exists receipt))) rejected;
    (* Preparation is offline and cannot run either Z3 or kubectl. An unsafe
       candidate still prepares successfully with both executables trapped. *)
    let fake_bin = local "fake-bin" in Unix.mkdir fake_bin 0o700;
    let log = local "unexpected-command" in
    List.iter (fun name -> let path = Filename.concat fake_bin name in
      write path ("#!/bin/sh\nprintf 'invoked\\n' >> " ^ Filename.quote log ^ "\nexit 99\n");
      Unix.chmod path 0o700) ["z3";"kubectl";"helm";"kustomize"];
    let old_path = Sys.getenv "PATH" in
    Fun.protect ~finally:(fun () -> Unix.putenv "PATH" old_path) (fun () ->
      Unix.putenv "PATH" fake_bin;
      let code,output,_ = run binary ["rbac";"prepare";input] in
      check "preparation needs no solver or cluster command" (code=0 && output=prepared.snapshot);
      check "no solver or kubectl process executed" (not (Sys.file_exists log)));
    let manifest = local "rendered bundle.yaml" in
    let items = array (field "items" (parse source)) in
    let workload = {|apiVersion: apps/v1
kind: Deployment
metadata: {name: frontend}
spec: {replicas: 2}
|} in
    let yaml = String.concat "\n---\n" (List.map K.Input.json items @ [workload]) in
    write manifest yaml;
    let args = ["rbac";"prepare";manifest;"--input-format";"yaml";"--rbac-only"] in
    let receipt2 = local "manifest-receipt.json" in
    let code,output,error = run binary (args @ ["--receipt";receipt2]) in
    check "explicit YAML bundle prepares" (code=0);
    check "RBAC selection reported on stderr" (contains error "excluded 1 non-RBAC objects");
    let parsed = parse output in
    check "all selected policy retained" (field "items" parsed=field "items" (parse prepared.snapshot));
    let r = parse (read receipt2) in
    check "manifest CLI schema 2" (field "schema_version" r=`Number "2");
    check "manifest receipt binds input" (field "sha256" (field "input" r)=`String (Sha256.string yaml));
    check "manifest receipt binds output" (field "sha256" (field "snapshot" r)=`String (Sha256.string output));
    check "manifest receipt is private" ((Unix.stat receipt2).Unix.st_perm land 0o777=0o600);
    no_output "existing schema 2 receipt" 1 (args @ ["--receipt";receipt2]);
    no_output "manifest mode opt-in" 2 ["rbac";"prepare";manifest];
    no_output "mixed manifests selection opt-in" 2 ["rbac";"prepare";manifest;"--input-format";"yaml"];
    List.iteri (fun i options -> no_output (Printf.sprintf "manifest options %d" i) 2
      (["rbac";"prepare";manifest] @ options))
      [["--namespace";"frontend"];["--rbac-only"];["--input-format";"auto"];
       ["--input-format";"yaml";"--input-format";"json"];
       ["--input-format";"yaml";"--namespace";"a";"--namespace";"b"];
       ["--input-format";"yaml";"--rbac-only";"--rbac-only"];
       ["--input-format";"yaml";"--namespace";"UPPER"]];
    let failed_receipt = local "failed-manifest-receipt.json" in
    write manifest (yaml ^ "\n---\nvalue: [broken\n");
    no_output "malformed later document" 2 (args @ ["--receipt";failed_receipt]);
    check "later document failure creates no receipt" (not (Sys.file_exists failed_receipt));
    write manifest yaml;
    Fun.protect ~finally:(fun () -> Unix.putenv "PATH" old_path) (fun () ->
      Unix.putenv "PATH" fake_bin;
      let code,_,_ = run binary args in
      check "manifest mode remains offline" (code=0 && not (Sys.file_exists log)));
    let normalized name =
      let source = enriched (read (fixture name)) in
      let export = local (name ^ "-export.json") in write export source;
      let code,output,_ = run binary ["rbac";"prepare";export] in
      check (name ^ " export prepares") (code=0);
      let output_path = local (name ^ "-snapshot.json") in write output_path output;output_path in
    let unsafe = normalized "01-unsafe" and deny_all = normalized "02-delete-workload-grants"
    and repaired = normalized "03-valid-repair" and regression = normalized "16-operator-regression" in
    let verify name path expected verdict clause =
      let code,output,error = run binary ["rbac";"verify";path;"--contract";contract;"--format";"json"] in
      check (name ^ " verification exit " ^ error) (code=expected);
      let report = parse output in
      check (name ^ " verification result") (field "result" report=`String verdict);
      Option.iter (fun kind -> check (name ^ " failing clause")
        (field "kind" (field "clause" report)=`String kind)) clause in
    verify "unsafe remains unsafe" unsafe 3 "violated" (Some "must_not_grant");
    verify "deny-all still loses functionality" deny_all 3 "violated" (Some "must_allow");
    verify "valid repair preserves contract" repaired 0 "proved" None;
    verify "operator regression satisfies candidate contract" regression 0 "proved" None;
    List.iter (fun (name,after,expected,verdict) ->
      let code,output,error = run binary ["rbac";"compare";unsafe;after;"--contract";contract;"--format";"json"] in
      check (name ^ " comparison exit " ^ error) (code=expected);
      let report = parse output in
      check (name ^ " comparison result") (field "result" report=`String verdict);
      if expected=3 then check "operator regression remains a preservation failure"
        (field "kind" (field "clause" report)=`String "must_preserve"))
      ["valid normalized repair",repaired,0,"proved";"normalized operator regression",regression,3,"violated"]);
  Printf.printf "RBAC prepare CLI: %d checks passed\n" !checks
