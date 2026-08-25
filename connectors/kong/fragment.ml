(* The decidability boundary for the Kong connector.

   A Kong route path is either a literal prefix or a regex. Both are now modelled
   — see {!Lower.path_condition} — so this module no longer rejects regexes
   wholesale. It rejects exactly what {!Regex.parse} cannot translate: constructs
   that are not regular (backreferences) or whose language we decline to guess at
   (possessive quantifiers, atomic groups, lookaround).

   Rejection remains WHOLE-CONFIG rather than per-route, and deliberately so: the
   route we cannot model may be exactly the one that decides the property, so
   verifying the rest and calling the result a proof would be unsound. *)

open Soundcheck_core

type finding = {
  service : string;
  route   : string;
  path    : string;
  why     : string;
}

(* Characters Kong treats as ordinary in a path. Anything outside this set forced
   the path to compile as a regex before Kong 3.0, when the marker was implicit. *)
let is_plain_path_char = function
  | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '.' | '-' | '_' | '~' | '/' | '%' ->
    true
  | _ -> false

(* Kong 3.x marks a regex path with a leading '~'; earlier versions inferred it
   from the characters present. Both are honoured here.

   Where the two readings disagree we treat the path as a regex. That is the safe
   direction: parsing a literal as a regex still yields the same language for
   ordinary characters, whereas missing a regex would mis-model the route. *)
let is_regex_path (p : string) : bool =
  (String.length p > 0 && p.[0] = '~')
  || not (String.for_all is_plain_path_char p)

(* Strip Kong 3.x's explicit marker before handing the pattern to the parser. *)
let pattern_of (p : string) : string =
  if String.length p > 0 && p.[0] = '~' then String.sub p 1 (String.length p - 1)
  else p

let findings (cfg : Ast.config) : finding list =
  List.concat_map
    (fun (s : Ast.service) ->
      List.concat_map
        (fun (r : Ast.route) ->
          List.filter_map
            (fun p ->
              if not (is_regex_path p) then None
              else
                match Regex.parse (pattern_of p) with
                | Ok _ -> None
                | Error why ->
                  Some { service = s.name; route = r.name; path = p; why })
            r.paths)
        s.routes)
    cfg.services

let describe (f : finding) =
  Printf.sprintf "route %S (service %S) path %S — %s" f.route f.service f.path
    f.why

(* Name every offender: the point of [unknown] is that the user can act on it, and
   a config stays unverifiable until each one is rewritten. *)
let reason (fs : finding list) : string =
  Printf.sprintf
    "unsupported fragment: %d route path(s) use regex constructs outside the \
     supported subset, so no verdict can be given for this config. %s. Rewriting \
     the path within the supported subset (literals, ., character classes, ?*+, \
     bounded repetition, alternation, grouping) makes it verifiable."
    (List.length fs)
    (String.concat "; " (List.map describe fs))

let check (cfg : Ast.config) : (unit, string) result =
  match findings cfg with [] -> Ok () | fs -> Error (reason fs)
