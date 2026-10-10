open Soundcheck_core
open Soundcheck_kong

let usage () =
  prerr_endline
    "usage: kong_model_oracle CONFIG PRINCIPAL SCHEME METHOD PATH HOST SNI [HEADER-NAME:VALUE ...]";
  exit 2

let parse_header value =
  match String.index_opt value ':' with
  | Some index ->
    let name = String.sub value 0 index |> String.lowercase_ascii in
    let contents =
      String.sub value (index + 1) (String.length value - index - 1)
      |> String.lowercase_ascii
    in
    (name, contents)
  | None ->
    prerr_endline (Printf.sprintf "invalid header %S (expected NAME:VALUE)" value);
    exit 2

let service_for_route (config : Ast.config) route =
  let services =
    List.filter_map
      (fun (service : Ast.service) ->
        if List.exists (fun (candidate : Ast.route) -> candidate.name = route) service.routes
        then Some service.name
        else None)
      config.services
    |> List.sort_uniq String.compare
  in
  match services with
  | [] -> "-"
  | [ service ] -> service
  | _ ->
    prerr_endline
      (Printf.sprintf "route name %S is not unique across services" route);
    exit 2

let read_file path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in channel)
    (fun () -> really_input_string channel (in_channel_length channel))

let confirm_unsupported source =
  (* Unsupported is a boundary check of the public verification pipeline, not
     agreement between a target decision and an invented model decision. In
     particular a solver timeout must never satisfy this expectation. *)
  match Verify.run ~property:(Verify.No_anonymous_access "/") source with
  | Ok { Report.result = Report.Unknown _;
         assurance = Some { status = Report.Unsupported; _ }; _ } ->
    print_endline "unsupported\tunknown";
    exit 0
  | _ ->
    prerr_endline "fragment rejection did not produce Unknown with Unsupported assurance";
    exit 2

let () =
  if Array.length Sys.argv < 8 then usage ();
  (* The fixture, not the policy decision, assigns the abstract principal.
     In particular an invalid/missing key is anonymous even if Kong permits it
     through an explicit anonymous-consumer fallback. *)
  let principal =
    match Sys.argv.(2) with
    | "anonymous" -> Ir.Anonymous
    | "authenticated" -> Ir.Authenticated "conformance-user"
    | value ->
      prerr_endline (Printf.sprintf "invalid probe principal %S" value);
      exit 2
  in
  let source = read_file Sys.argv.(1) in
  let config =
    match Parse.parse_string source with
    | Ok config -> config
    | Error error -> prerr_endline error; exit 2
  in
  (match Validate.check config with
   | Error error -> prerr_endline error; exit 2
   | Ok () -> ());
  (match Fragment.check config with
   | Error _ -> confirm_unsupported source
   | Ok () -> ());
  let headers =
    List.init (Array.length Sys.argv - 8) (fun index ->
        parse_header Sys.argv.(index + 8))
  in
  let request : Ir.request =
    { principal;
      action = String.uppercase_ascii Sys.argv.(4);
      resource = Sys.argv.(5);
      context = headers;
      source = 0l;
      host = String.lowercase_ascii Sys.argv.(6);
      scheme = String.lowercase_ascii Sys.argv.(3);
      sni = String.lowercase_ascii Sys.argv.(7) }
  in
  let policy = Lower.to_policy config in
  let routes =
    policy.rules
    |> List.filter (Ir.selected policy request)
    |> List.map (fun (rule : Ir.rule) -> rule.id)
    |> List.sort_uniq String.compare
  in
  let no_route_possible =
    not
      (List.exists
         (fun (rule : Ir.rule) -> rule.match_complete && Ir.matches rule.match_ request)
         policy.rules)
  in
  (* Internal harness protocol, not the public report schema. Unknown ordering
     keeps every possible routing identity. The harness checks containment and
     must <= actual <= may, and reports conservative checks separately. *)
  Printf.printf "supported\t%s\t%s\n"
    (Ir.evaluate policy request |> Ir.string_of_decision |> String.lowercase_ascii)
    (if Ir.definitely_allows policy request then "allow" else "deny");
  (* A possible regex/header/host match may fail in the target. Unless at least
     one complete route definitely matches, "no selected route" is also a
     possible identity, independent of the may/must policy decisions above. *)
  if no_route_possible then print_endline "-\t-";
  List.iter
    (fun route -> Printf.printf "%s\t%s\n" route (service_for_route config route))
    routes
