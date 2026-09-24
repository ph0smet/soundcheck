let fail format = Printf.ksprintf failwith format

let field name = function
  | `O fields -> List.assoc_opt name fields
  | _ -> None

let require_field where name value =
  match field name value with
  | Some found -> found
  | None -> fail "%s omitted %S" where name

let require_string where name value =
  match require_field where name value with
  | `String found -> found
  | _ -> fail "%s field %S was not a string" where name

let require_true where name value =
  match require_field where name value with
  | `Bool true -> ()
  | _ -> fail "%s field %S was not true" where name

let read_file path =
  let channel = open_in_bin path in
  let length = in_channel_length channel in
  let source = really_input_string channel length in
  close_in channel;
  source

let () =
  if Array.length Sys.argv <> 2 then fail "expected action.yml path";
  let action =
    match Yaml.of_string (read_file Sys.argv.(1)) with
    | Ok value -> value
    | Error (`Msg message) -> fail "invalid action.yml: %s" message
  in
  let inputs = require_field "action" "inputs" action in
  (match inputs with
   | `O fields ->
     let names = List.map fst fields |> List.sort String.compare in
     if names <> [ "config"; "contract" ] then
       fail "Action inputs changed: expected only config and contract";
     List.iter
       (fun name ->
         require_true ("input " ^ name) "required"
           (require_field "inputs" name inputs))
       names
   | _ -> fail "Action inputs were not an object");
  let runs = require_field "action" "runs" action in
  if require_string "runs" "using" runs <> "composite" then
    fail "Action must remain composite";
  let steps = require_field "runs" "steps" runs in
  let verify_script =
    match steps with
    | `A values ->
      List.find_map
        (fun step ->
          match field "name" step, field "run" step with
          | Some (`String "Verify frozen contract"), Some (`String script) ->
            Some script
          | _ -> None)
        values
    | _ -> None
  in
  match verify_script with
  | Some script
    when String.contains script '\n'
         && String.ends_with ~suffix:"--format github\n" script -> ()
  | _ -> fail "verification step does not invoke the GitHub annotation format"
