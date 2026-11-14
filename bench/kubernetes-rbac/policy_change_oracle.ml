(* Production adapter for comparison with the independent pinned native oracle.
   Never used as the reference and never runs the access solver. *)
module K = Soundcheck_kubernetes_rbac
let read path = let c = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr c) (fun () ->
    let size = in_channel_length c in
    if size > 16*1024*1024 then failwith "input exceeds 16 MiB";
    really_input_string c size)
let () =
  if Array.length Sys.argv<>4 then (prerr_endline "expected BEFORE AFTER CONTRACT";exit 2);
  let result = Result.bind (K.Change_spec.of_string (read Sys.argv.(3))) (fun spec ->
    K.Policy_change.authorize spec ~before:(read Sys.argv.(1)) ~after:(read Sys.argv.(2))) in
  let output = match result with
    | Error reason -> `O ["result",`String "unknown";"reason",`String reason;"authorization",`Null]
    | Ok authorization -> `O ["result",`String (if authorization.allowed then "authorization_allowed" else "authorization_failed");
        "reason",`String authorization.reason;"authorization",K.Input.parse (K.Policy_change.authorization_json authorization)] in
  print_endline (K.Input.json output)
