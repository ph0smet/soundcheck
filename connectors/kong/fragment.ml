(* The decidability boundary for the Kong connector.

   {!Smt_encode} models a route path as a literal prefix ([str.prefixof]). A Kong
   regex path is therefore NOT modelled: encoded literally it matches essentially
   nothing, so the route drops out of the analysis and the verifier can report a
   proof that does not hold. A false proof is the one outcome this tool must never
   produce, so rather than under-approximate we refuse the config outright and
   return [unknown].

   Rejection is WHOLE-CONFIG, not per-route, and that is deliberate for v0: the
   route we cannot model may be exactly the one that decides the property, so
   verifying the remaining routes and calling the result a proof would be unsound.
   A finer-grained answer (prove what is provable, flag only when a regex route
   could have mattered) is possible later, but it has to argue that the unmodelled
   route is irrelevant, which is real work rather than a smaller patch. *)

type finding = {
  service : string;
  route   : string;
  path    : string;
}

(* Characters Kong treats as ordinary in a path. Anything outside this set forced
   the path to compile as a regex before Kong 3.0, when the marker was implicit. *)
let is_plain_path_char = function
  | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '.' | '-' | '_' | '~' | '/' | '%' ->
    true
  | _ -> false

(* Kong 3.x marks a regex path with a leading '~'; earlier versions inferred it
   from the characters present. Both are honoured here.

   Where the two readings disagree we flag. Over-flagging costs an [unknown] and
   is recoverable; under-flagging costs a false proof and is not. *)
let is_regex_path (p : string) : bool =
  (String.length p > 0 && p.[0] = '~')
  || not (String.for_all is_plain_path_char p)

let findings (cfg : Ast.config) : finding list =
  List.concat_map
    (fun (s : Ast.service) ->
      List.concat_map
        (fun (r : Ast.route) ->
          List.filter_map
            (fun p ->
              if is_regex_path p then
                Some { service = s.name; route = r.name; path = p }
              else None)
            r.paths)
        s.routes)
    cfg.services

let describe (f : finding) =
  Printf.sprintf "route %S (service %S) path %S" f.route f.service f.path

(* Name every offender: the point of [unknown] is that the user can act on it, and
   a config is only unverifiable until each one is rewritten or the fragment is
   widened. *)
let reason (fs : finding list) : string =
  Printf.sprintf
    "unsupported fragment: regex route paths are not modelled, so no verdict can \
     be given for this config. Offending: %s. Paths are encoded as literal \
     prefixes; treating a regex as a literal would drop the route from the \
     analysis and could report a proof that does not hold."
    (String.concat "; " (List.map describe fs))

let check (cfg : Ast.config) : (unit, string) result =
  match findings cfg with [] -> Ok () | fs -> Error (reason fs)
