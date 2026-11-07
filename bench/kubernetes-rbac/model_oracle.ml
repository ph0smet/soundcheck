open Soundcheck_kubernetes_rbac

let read path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
    let length = in_channel_length channel in
    if length > 16 * 1024 * 1024 then failwith "input exceeds 16 MiB";
    really_input_string channel length)

let () =
  let output = try
    if Array.length Sys.argv <> 4 then failwith "usage: model_oracle MANIFEST CONTRACT REQUESTS";
    let ( let* ) = Result.bind in
    let result =
      let* spec = Contract_spec.of_string (read Sys.argv.(2)) in
      let* snapshot = Snapshot.of_string (read Sys.argv.(1)) in
      let* requests = Evaluate.requests spec (read Sys.argv.(3)) in
      let policy = Lower.policy spec snapshot in
      Ok (`O ["status",`String "supported";
              "decisions",Evaluate.decisions policy requests;
              "matrix_smt",`String (Evaluate.matrix_smt policy requests)]) in
    match result with Ok value -> value | Error reason ->
      `O ["status",`String "unknown";"reason",`String reason;"decisions",`A []]
  with Sys_error reason | Failure reason ->
    `O ["status",`String "unknown";"reason",`String reason;"decisions",`A []] in
  print_endline (Input.json output)
