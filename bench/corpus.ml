(* Corpus regression runner. Verify every case under kong/cases/ and check the
   Report JSON against its committed expected.json golden. Exits nonzero on any
   mismatch, so `dune test` gates the whole corpus.

   Each case is a real-world-inspired Kong decK misconfig (or a correct baseline);
   the golden is the stable Report JSON contract the engine produces.

   WITNESS STRINGS ARE NOT COMPARED. A [sat] result is *some* satisfying
   assignment and the solver is free to return any of them: `str.prefixof "/login"
   path` is satisfied by "/login", "/loginA", "/loginZZZ" and so on, and different
   z3 versions genuinely pick differently. Pinning the one our machine happened to
   produce made the corpus fail on a solver upgrade rather than on a real
   regression. So the diff masks [path] and [action], and the witness is instead
   CHECKED against the reference semantics: it must really be allowed by the
   policy, and really be in the property's forbidden class. That is a stronger
   claim than string equality — it asserts the counterexample is genuine rather
   than merely unchanged. Everything that IS deterministic (result, property,
   route, service, shadowed_route, schema_version) is still compared exactly. *)

open Soundcheck_core
open Soundcheck_kong

let cases_dir = "kong/cases"

let read path =
  let ic = open_in_bin path in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic;
  s

(* A case may name the property to check in an optional "property" file; absent
   means the default no-anonymous-access (/admin). Returns the variant used to run
   the case, plus the core template when it has one — no-shadowed-routes is asked
   per rule pair rather than as a single query over requests, so it has none. *)
let property_of dir : Verify.property * Property.t option =
  let f = Filename.concat dir "property" in
  let name =
    if Sys.file_exists f then String.trim (read f) else "no-anonymous-access"
  in
  match name with
  | "no-anonymous-access" ->
    ( Verify.No_anonymous_access "/admin",
      Some (Property.no_anonymous_access ~path_prefix:"/admin") )
  | "rate-limit-on-public" ->
    (Verify.Rate_limit_on_public, Some Property.rate_limit_on_public)
  | "no-shadowed-routes" -> (Verify.No_shadowed_routes, None)
  | other -> failwith (Printf.sprintf "%s: unknown property %S" dir other)

(* Replace the string value of ["key"] with a placeholder. The JSON comes from our
   own emitter, so the shape is known: "key":"<escaped>". *)
let mask (key : string) (json : string) : string =
  let tag = Printf.sprintf "\"%s\":\"" key in
  let tl = String.length tag and n = String.length json in
  let buf = Buffer.create n in
  let rec go i =
    if i >= n then ()
    else if i + tl <= n && String.sub json i tl = tag then begin
      Buffer.add_string buf tag;
      Buffer.add_string buf "<witness>";
      (* skip to the closing quote, honouring backslash escapes *)
      let rec skip j =
        if j >= n then j
        else if json.[j] = '\\' then skip (j + 2)
        else if json.[j] = '"' then j
        else skip (j + 1)
      in
      let close = skip (i + tl) in
      Buffer.add_char buf '"';
      go (close + 1)
    end
    else begin
      Buffer.add_char buf json.[i];
      go (i + 1)
    end
  in
  go 0;
  Buffer.contents buf

let mask_witness json = json |> mask "path" |> mask "action"

let request_of (ce : Report.counterexample) : Ir.request =
  { principal =
      (if ce.principal = "anonymous" then Ir.Anonymous
       else Ir.Authenticated "user");
    action = ce.action;
    resource = ce.path;
    context = [] }

(* Is the reported counterexample a genuine one? Checked with {!Ir.evaluate}, the
   concrete reference semantics, which is independent of the SMT encoding — so
   this also cross-checks encoder against evaluator. *)
let validate config (prop : Property.t option) (ce : Report.counterexample) :
    string option =
  match Parse.parse_string config with
  | Error e -> Some ("config parse error: " ^ e)
  | Ok cfg -> (
    let policy = Lower.to_policy cfg in
    let req = request_of ce in
    if Ir.evaluate policy req <> Ir.Allow then
      Some
        (Printf.sprintf "witness %S is not actually allowed by the policy" ce.path)
    else
      match prop with
      | Some p when not (Ir.matches p.Property.forbidden_when req) ->
        Some
          (Printf.sprintf "witness %S is not in the property's forbidden class"
             ce.path)
      | _ -> None)

let () =
  let cases =
    Sys.readdir cases_dir |> Array.to_list
    |> List.filter (fun c -> Sys.is_directory (Filename.concat cases_dir c))
    |> List.sort compare
  in
  let failures = ref 0 in
  let fail case fmt = Printf.ksprintf (fun s ->
    incr failures;
    Printf.printf "[FAIL]  %s\n%s" case s) fmt
  in
  List.iter
    (fun case ->
      let dir = Filename.concat cases_dir case in
      let config = read (Filename.concat dir "config.yaml") in
      let expected = String.trim (read (Filename.concat dir "expected.json")) in
      let property, template = property_of dir in
      match Verify.run ~property config with
      | Error e ->
        incr failures;
        Printf.printf "[ERROR] %-20s config parse error: %s\n" case e
      | Ok report -> (
        let got = Report.to_json report in
        if mask_witness got <> mask_witness expected then
          fail case "  expected: %s\n  got:      %s\n" expected got
        else
          (* Shape matches; now the witness itself must hold up. *)
          match report.Report.result with
          | Report.Violated ce -> (
            match validate config template ce with
            | Some why -> fail case "  %s\n" why
            | None -> Printf.printf "[ok]    %s\n" case)
          | _ -> Printf.printf "[ok]    %s\n" case))
    cases;
  if !failures > 0 then (
    Printf.printf "\n%d of %d case(s) failed\n" !failures (List.length cases);
    exit 1)
  else Printf.printf "\nall %d cases passed\n" (List.length cases)
