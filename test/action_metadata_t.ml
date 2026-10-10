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

let require_false where name value =
  match require_field where name value with
  | `Bool false | `String "false" -> ()
  | _ -> fail "%s field %S was not false" where name

let read_file path =
  let channel = open_in_bin path in
  let length = in_channel_length channel in
  let source = really_input_string channel length in
  close_in channel;
  source

let write_file path source =
  let channel = open_out_bin path in
  Fun.protect ~finally:(fun () -> close_out channel)
    (fun () -> output_string channel source)

let check_build_guard script =
  let root = Filename.temp_file "soundcheck-action-build-" "" in
  Sys.remove root;
  Sys.mkdir root 0o700;
  let script_path = Filename.concat root "guard.sh" in
  write_file script_path script;
  let run case expected setup cleanup =
    let workspace = Filename.concat root case in
    Sys.mkdir workspace 0o700;
    setup workspace;
    let status =
      Sys.command
        (Printf.sprintf "GITHUB_WORKSPACE=%s bash %s >/dev/null 2>&1"
           (Filename.quote workspace) (Filename.quote script_path))
    in
    if status <> expected then
      fail "build guard %s: expected exit %d, got %d (fixture %s)"
        case expected status root;
    cleanup workspace;
    Sys.rmdir workspace
  in
  let no_op _ = () in
  run "fresh" 0 no_op no_op;
  run "file" 1
    (fun workspace -> write_file (Filename.concat workspace "_opam") "retained")
    (fun workspace ->
      let file = Filename.concat workspace "_opam" in
      if read_file file <> "retained" then fail "guard changed candidate _opam file";
      Sys.remove file);
  run "directory" 1
    (fun workspace ->
      let dir = Filename.concat workspace "_opam" in
      Sys.mkdir dir 0o700;
      write_file (Filename.concat dir "marker") "retained")
    (fun workspace ->
      let dir = Filename.concat workspace "_opam" in
      let marker = Filename.concat dir "marker" in
      if read_file marker <> "retained" then fail "guard changed candidate _opam directory";
      Sys.remove marker;
      Sys.rmdir dir);
  List.iter
    (fun broken ->
      run (if broken then "broken-link" else "link") 1
        (fun workspace ->
          let target = Filename.concat workspace "target" in
          if not broken then Sys.mkdir target 0o700;
          if Sys.command
               (Printf.sprintf "ln -s %s %s" (Filename.quote target)
                  (Filename.quote (Filename.concat workspace "_opam"))) <> 0
          then fail "cannot create local switch symlink fixture")
        (fun workspace ->
          let link = Filename.concat workspace "_opam" in
          if Sys.command ("test -L " ^ Filename.quote link) <> 0 then
            fail "guard removed candidate _opam symlink";
          Sys.remove link;
          if not broken then Sys.rmdir (Filename.concat workspace "target")))
    [ false; true ];
  Sys.remove script_path;
  Sys.rmdir root

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
  let steps =
    match require_field "runs" "steps" runs with
    | `A values -> values
    | _ -> fail "Action steps were not an array"
  in
  let step_named name =
    match List.find_opt (fun step -> field "name" step = Some (`String name)) steps with
    | Some step -> step
    | None -> fail "Action omitted step %S" name
  in
  let guard = step_named "Require a fresh Action build switch" in
  (match steps with
   | first :: _ when first = guard -> ()
   | _ -> fail "fresh-switch guard must run before setup or any other Action step");
  check_build_guard (require_string "fresh-switch guard" "run" guard);
  let setup = step_named "Set up OCaml" in
  let setup_inputs = require_field "OCaml setup" "with" setup in
  List.iter (fun name -> require_false "OCaml setup" name setup_inputs)
    [ "opam-pin"; "cache"; "dune-cache" ];
  List.iter
    (fun (name, command) ->
      let step = step_named name in
      if require_string name "working-directory" step <> "${{ github.action_path }}" then
        fail "%s must use trusted Action sources" name;
      if require_string name "run" step <> command then
        fail "%s must select the isolated workspace switch explicitly" name)
    [ ("Install Soundcheck dependencies",
       "opam install --switch=\"$GITHUB_WORKSPACE\" . --deps-only --yes");
      ("Build Soundcheck",
       "opam exec --switch=\"$GITHUB_WORKSPACE\" -- dune build cli/main.exe") ];
  let verify_step =
    List.find_map
      (fun step ->
        match field "name" step, field "run" step with
        | Some (`String "Verify frozen contract"), Some (`String _) -> Some step
        | _ -> None)
      steps
  in
  match verify_step with
  | None -> fail "Action omitted the approved-contract verification step"
  | Some step ->
    let script = require_string "verification step" "run" step in
    if String.trim script <> "bash \"$GITHUB_ACTION_PATH/scripts/verify-approved-contract.sh\"" then
      fail "verification must invoke the helper from its trusted Action source";
    let env = require_field "verification step" "env" step in
    List.iter
      (fun (name, expected) ->
        if require_string "verification environment" name env <> expected then
          fail "verification input %s was not safely passed through the environment" name)
      [ ("SOUNDCHECK_CONFIG_INPUT", "${{ inputs.config }}");
        ("SOUNDCHECK_CONTRACT_INPUT", "${{ inputs.contract }}") ];
    print_endline "Action metadata checks passed"
