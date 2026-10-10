(* Bounded capture of a directly launched POSIX process. Input is a regular SMT
   file passed in argv, not a pipe: create_process remains usable in embedding
   applications that have started OCaml threads/domains, with no SIGPIPE policy
   changes or OCaml fork child. We supervise only this PID, not its descendants. *)

type t = {
  pid : int;
  mutable output : Unix.file_descr option;
  mutable error : Unix.file_descr option;
  mutable status : Unix.process_status option;
  stdout : Buffer.t;
  stderr : Buffer.t;
  deadline : float;
}

exception Failed of string

let output_limit = 4 * 1024 * 1024
let close descriptor = try Unix.close descriptor with Unix.Unix_error _ -> ()

(* External output and OS errors are bytes, not guaranteed UTF-8. Normalize
   only diagnostic text: successful stdout must reach the protocol decoder
   unchanged. Bound excerpts without splitting a valid Unicode scalar, preserve
   valid Unicode, and visibly escape each invalid byte instead of losing it. *)
let diagnostic text =
  let text = String.trim text in
  let length = String.length text in
  let limit = min length 2048 in
  let output = Buffer.create limit in
  let rec copy index =
    if index >= limit then index
    else
      let decoded = String.get_utf_8_uchar text index in
      if Uchar.utf_decode_is_valid decoded then
        let width = Uchar.utf_decode_length decoded in
        if index + width > limit then index
        else begin
          Buffer.add_substring output text index width;
          copy (index + width)
        end
      else begin
        Buffer.add_string output (Printf.sprintf "\\x%02x" (Char.code text.[index]));
        copy (index + 1)
      end
  in
  let consumed = copy 0 in
  if consumed < length then Buffer.add_string output " [truncated]";
  Buffer.contents output

let error_message exception_ =
  diagnostic
    (match exception_ with
     | Unix.Unix_error (error, operation, argument) ->
       Printf.sprintf "%s(%s): %s" operation argument (Unix.error_message error)
     | Sys_error reason -> reason
     | exception_ -> Printexc.to_string exception_)

let deadline timeout =
  if not (Float.is_finite timeout) || timeout <= 0. then
    Error "solver timeout must be a finite positive number of seconds"
  else Ok (Unix.gettimeofday () +. timeout)

let start ~deadline binary arguments =
  if Unix.gettimeofday () >= deadline then raise (Failed "solver process timed out");
  let descriptors = ref [] in
  let is_standard descriptor =
    List.mem descriptor [ Unix.stdin; Unix.stdout; Unix.stderr ]
  in
  let above_standard descriptor =
    if not (is_standard descriptor) then descriptor
    else
      let rec duplicate () =
        let copy = Unix.dup ~cloexec:true descriptor in
        descriptors := copy :: !descriptors;
        if is_standard copy then duplicate () else copy
      in
      duplicate ()
  in
  let pipe () =
    let read, write = Unix.pipe ~cloexec:true () in
    descriptors := read :: write :: !descriptors;
    (* Initially closed standard descriptors can be reused by pipe. Keep those
       as temporary reservations, and pass only descriptors above 2 to spawn:
       a same-fd redirection can otherwise retain CLOEXEC and disappear at exec. *)
    (above_standard read, above_standard write)
  in
  try
    let output_read, output_write = pipe () in
    let error_read, error_write = pipe () in
    let input = Unix.openfile "/dev/null" [ Unix.O_RDONLY; Unix.O_CLOEXEC ] 0 in
    descriptors := input :: !descriptors;
    List.iter Unix.set_nonblock [ output_read; error_read ];
    let pid =
      Unix.create_process binary (Array.of_list (binary :: arguments))
        input output_write error_write
    in
    List.iter
      (fun descriptor ->
        if descriptor <> output_read && descriptor <> error_read then close descriptor)
      !descriptors;
    { pid; output = Some output_read; error = Some error_read; status = None;
      stdout = Buffer.create 256; stderr = Buffer.create 128; deadline }
  with exception_ ->
    List.iter close !descriptors;
    raise exception_

let poll_status process =
  match process.status with
  | Some _ -> ()
  | None ->
    (try
       match Unix.waitpid [ Unix.WNOHANG ] process.pid with
       | 0, _ -> ()
       | _, status -> process.status <- Some status
     with Unix.Unix_error (Unix.EINTR, _, _) -> ())

let kill process =
  (* An unreaped child retains its PID, so do not signal a PID after reaping. *)
  if process.status = None then
    (try Unix.kill process.pid Sys.sigkill with Unix.Unix_error _ -> ())

let cleanup process =
  Option.iter close process.output;
  Option.iter close process.error;
  process.output <- None;
  process.error <- None;
  if process.status = None then begin
    kill process;
    (* Cleanup itself is bounded, including an OS-level stalled exit. *)
    let until = Unix.gettimeofday () +. 0.5 in
    while process.status = None && Unix.gettimeofday () < until do
      poll_status process;
      if process.status = None then
        (try ignore (Unix.select [] [] [] 0.005)
         with Unix.Unix_error (Unix.EINTR, _, _) -> ())
    done
  end

let excerpt buffer =
  diagnostic (Buffer.contents buffer)

let diagnostics process reason =
  let stdout = excerpt process.stdout and stderr = excerpt process.stderr in
  reason
  ^ (if stdout = "" then "" else "; stdout: " ^ stdout)
  ^ (if stderr = "" then "" else "; stderr: " ^ stderr)

let read_ready process descriptor buffer set_closed =
  let bytes = Bytes.create 8192 in
  try
    let count = Unix.read descriptor bytes 0 (Bytes.length bytes) in
    if count = 0 then begin close descriptor; set_closed () end
    else begin
      let available = output_limit - Buffer.length buffer in
      Buffer.add_subbytes buffer bytes 0 (min available count);
      if count > available then begin
        kill process;
        raise (Failed "solver output exceeded the 4 MiB per-stream limit")
      end
    end
  with
  | Unix.Unix_error ((Unix.EAGAIN | Unix.EWOULDBLOCK | Unix.EINTR), _, _) -> ()

let step process =
  if Unix.gettimeofday () >= process.deadline then begin
    kill process;
    raise (Failed "solver process timed out")
  end;
  poll_status process;
  let readers = List.filter_map Fun.id [ process.output; process.error ] in
  let wait = max 0. (min 0.02 (process.deadline -. Unix.gettimeofday ())) in
  let readable, _, _ =
    try Unix.select readers [] [] wait
    with Unix.Unix_error (Unix.EINTR, _, _) -> ([], [], [])
  in
  Option.iter
    (fun descriptor ->
      if List.mem descriptor readable then
        read_ready process descriptor process.stdout (fun () -> process.output <- None))
    process.output;
  Option.iter
    (fun descriptor ->
      if List.mem descriptor readable then
        read_ready process descriptor process.stderr (fun () -> process.error <- None))
    process.error

let complete process =
  while process.output <> None || process.error <> None || process.status = None do
    step process
  done;
  match process.status with
  | Some (Unix.WEXITED 0) when String.trim (Buffer.contents process.stderr) = "" ->
    Buffer.contents process.stdout
  | Some (Unix.WEXITED 0) -> raise (Failed "solver wrote diagnostics to stderr")
  | Some (Unix.WEXITED code) ->
    raise (Failed (Printf.sprintf "solver exited with status %d" code))
  | Some (Unix.WSIGNALED signal) ->
    raise (Failed (Printf.sprintf "solver terminated by signal %d" signal))
  | Some (Unix.WSTOPPED signal) ->
    raise (Failed (Printf.sprintf "solver stopped by signal %d" signal))
  | None -> assert false

let run ~deadline binary arguments =
  try
    let process = start ~deadline binary arguments in
    Fun.protect ~finally:(fun () -> cleanup process) (fun () ->
        try Ok (complete process) with
        | Failed reason -> Error (diagnostics process reason)
        | (Unix.Unix_error _ | Sys_error _) as exception_ ->
          Error (diagnostics process (error_message exception_)))
  with
  | Failed reason -> Error (diagnostic reason)
  | (Unix.Unix_error _ | Sys_error _) as exception_ -> Error (error_message exception_)
