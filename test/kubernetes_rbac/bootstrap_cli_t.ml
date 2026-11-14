module K = Soundcheck_kubernetes_rbac
let checks = ref 0
let check label value = incr checks; if not value then failwith ("bootstrap CLI: " ^ label)
let ok = function Ok value -> value | Error reason -> failwith reason
let read path = let input=open_in_bin path in
  Fun.protect ~finally:(fun ()->close_in_noerr input) (fun ()->really_input_string input (in_channel_length input))
let run binary args =
  let out=Filename.temp_file "bootstrap-out" ".json" and err=Filename.temp_file "bootstrap-err" ".txt" in
  Fun.protect ~finally:(fun ()->List.iter Sys.remove [out;err]) (fun ()->
    let o=Unix.openfile out [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 and e=Unix.openfile err [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let pid=Unix.create_process binary (Array.of_list (binary::args)) Unix.stdin o e in
    Unix.close o;Unix.close e;
    let _,status=Unix.waitpid [] pid in
    (match status with Unix.WEXITED code->code | _->99),read out,read err)

let () =
  let binary=Sys.argv.(1) in
  let base=["rbac";"bootstrap";"--kubernetes-version";"1.34.0"] in
  List.iter (fun pack ->
    let expected=ok (K.Bootstrap.prepare ~kubernetes_version:"1.34.0" ~packs:[pack]) in
    let code,output,_=run binary (base@["--pack";pack]) in
    check ("selection " ^ pack) (code=0 && output=expected.snapshot)) K.Bootstrap.available_packs;
  let args=List.concat_map (fun pack->["--pack";pack]) K.Bootstrap.available_packs in
  let code,output,_=run binary (base@args) in
  check "all explicit selections" (code=0 && output=(ok (K.Bootstrap.prepare
    ~kubernetes_version:"1.34.0" ~packs:K.Bootstrap.available_packs)).snapshot);
  List.iter (fun args ->
    let code,output,_=run binary (["rbac";"bootstrap"]@args) in
    check "unsupported or implicit argument rejected without snapshot" (code=2 && output=""))
    [[];["--pack";"view"];["--kubernetes-version";"1.34.0"];
     ["--kubernetes-version";"1.34.1";"--pack";"view"];
     ["--kubernetes-version";"1.34.0";"--kubernetes-version";"1.34.0";"--pack";"view"];
     ["--kubernetes-version";"1.34.0";"--pack";"view";"--pack";"view"];
     ["--kubernetes-version";"1.34.0";"--pack";"unknown"];
     ["--kubernetes-version";"1.34.0";"--pack";"view";"--namespace";"apps"];
     ["--kubernetes-version";"1.34.0";"--pack";"view";"--all"]];
  let receipt=Filename.temp_file "bootstrap-receipt" ".json" in
  Fun.protect ~finally:(fun ()->if Sys.file_exists receipt then Sys.remove receipt) (fun ()->
    let code,output,_=run binary (base@["--pack";"view";"--receipt";receipt]) in
    check "existing receipt fails before snapshot" (code=1 && output="" && read receipt="");
    Sys.remove receipt;
    let code,output,_=run binary (base@["--pack";"view";"--receipt";receipt]) in
    let expected=ok (K.Bootstrap.prepare ~kubernetes_version:"1.34.0" ~packs:["view"]) in
    check "receipt and snapshot same library semantics" (code=0 && output=expected.snapshot && String.trim (read receipt)=expected.receipt);
    check "receipt remains private" ((Unix.stat receipt).Unix.st_perm land 0o077=0);
    let before=read receipt in
    let code,output,_=run binary (base@["--pack";"view";"--receipt";receipt;"--receipt";receipt]) in
    check "duplicate receipt flag does not mutate file" (code=2 && output="" && read receipt=before));
  Printf.printf "bootstrap CLI: %d checks passed\n" !checks
