(* Corpus regression runner. Verify every case under kong/cases/ and diff the
   Report JSON against its committed expected.json golden. Exits nonzero on any
   mismatch, so `dune test` gates the whole corpus.

   Each case is a real-world-inspired Kong decK misconfig (or a correct baseline);
   the golden is the stable Report JSON contract the engine produces. All bucket-A
   cases are checked against the single path prefix the no-anonymous-access
   property ships with today (/admin). *)

open Soundcheck_kong

let cases_dir = "kong/cases"

let read path =
  let ic = open_in_bin path in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic;
  s

(* A case may name the property to check in an optional "property" file; absent
   means the default no-anonymous-access (/admin). *)
let property_of dir : Verify.property =
  let f = Filename.concat dir "property" in
  let name = if Sys.file_exists f then String.trim (read f) else "no-anonymous-access" in
  match name with
  | "no-anonymous-access" -> Verify.No_anonymous_access "/admin"
  | "rate-limit-on-public" -> Verify.Rate_limit_on_public
  | other -> failwith (Printf.sprintf "%s: unknown property %S" dir other)

let () =
  let cases =
    Sys.readdir cases_dir |> Array.to_list
    |> List.filter (fun c -> Sys.is_directory (Filename.concat cases_dir c))
    |> List.sort compare
  in
  let failures = ref 0 in
  List.iter
    (fun case ->
      let dir = Filename.concat cases_dir case in
      let config = read (Filename.concat dir "config.yaml") in
      let expected = String.trim (read (Filename.concat dir "expected.json")) in
      match Verify.run ~config ~property:(property_of dir) with
      | Error e ->
        incr failures;
        Printf.printf "[ERROR] %-20s config parse error: %s\n" case e
      | Ok report ->
        let got = Soundcheck_core.Report.to_json report in
        if got = expected then Printf.printf "[ok]    %s\n" case
        else begin
          incr failures;
          Printf.printf "[FAIL]  %s\n  expected: %s\n  got:      %s\n"
            case expected got
        end)
    cases;
  if !failures > 0 then (
    Printf.printf "\n%d of %d case(s) failed\n" !failures (List.length cases);
    exit 1)
  else Printf.printf "\nall %d cases passed\n" (List.length cases)
