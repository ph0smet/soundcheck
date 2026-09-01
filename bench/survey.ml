(* Survey real decK configs: what do they actually contain?

   Every case in kong/cases is one we wrote, so the project has been reasoning
   about real-world configs from intuition. This walks a directory of decK YAML
   and reports what is really there, so decisions about what to model next rest on
   counts rather than guesses. Three questions in particular:

   - which path constructs appear, and how much of the residual [unknown] set is
     genuinely out of the supported regex fragment;
   - whether the auth / rate-limit / admin-port recognition lists are complete, or
     whether real configs lean on plugins we do not know;
   - which routing dimensions matter — hosts, headers and SNIs are unmodelled and
     declared out of scope, and this says how often that scope bites.

   Deliberately uses Soundcheck's OWN parser and fragment check, so the numbers
   describe what the tool sees rather than what some other YAML reader would.
   Fields we do not model are read straight off the YAML.

   Usage: dune exec bench/survey.exe -- <dir> [<dir> ...] *)

open Soundcheck_core
open Soundcheck_kong

let read path =
  let ic = open_in_bin path in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic;
  s

let rec yaml_files dir acc =
  match Sys.readdir dir with
  | entries ->
    Array.fold_left
      (fun acc e ->
        let p = Filename.concat dir e in
        if Sys.is_directory p then if e = ".git" then acc else yaml_files p acc
        else if Filename.check_suffix p ".yaml" || Filename.check_suffix p ".yml"
        then p :: acc
        else acc)
      acc entries
  | exception Sys_error _ -> acc

(* --- raw YAML helpers, for fields the IR does not model --- *)

let member k (v : Yaml.value) = match v with `O kvs -> List.assoc_opt k kvs | _ -> None
let seq = function Some (`A xs) -> xs | _ -> []
let str_seq v = List.filter_map (function `String s -> Some s | _ -> None) (seq v)

type counter = (string, int) Hashtbl.t

let bump (t : counter) k = Hashtbl.replace t k (1 + Option.value ~default:0 (Hashtbl.find_opt t k))

let top (t : counter) n =
  Hashtbl.fold (fun k v acc -> (k, v) :: acc) t []
  |> List.sort (fun (_, a) (_, b) -> compare b a)
  |> fun l -> List.filteri (fun i _ -> i < n) l

let () =
  let dirs = List.tl (Array.to_list Sys.argv) in
  if dirs = [] then (prerr_endline "usage: survey <dir> [<dir> ...]"; exit 2);
  let files = List.concat_map (fun d -> yaml_files d []) dirs in

  let deck_files = ref 0 and services = ref 0 and routes = ref 0 in
  let paths_total = ref 0 and paths_literal = ref 0 in
  let regex_explicit = ref 0 and regex_implicit = ref 0 in
  let regex_supported = ref 0 in
  let rejected : counter = Hashtbl.create 16 in
  let plugins : counter = Hashtbl.create 64 in
  let unknown_plugins : counter = Hashtbl.create 64 in
  let with_hosts = ref 0 and with_headers = ref 0 and with_snis = ref 0
  and with_methods = ref 0 in
  let regex_priority_set = ref 0 in
  let ports : counter = Hashtbl.create 16 in
  let admin_upstreams = ref 0 in

  (* Everything the connector claims to recognise, so "unknown" below means
     genuinely unrecognised rather than merely uncommon. *)
  let known_plugin n =
    Lower.is_auth_plugin n || Lower.is_rate_limit_plugin n || n = "ip-restriction"
  in

  List.iter
    (fun file ->
      match Yaml.of_string (read file) with
      | Error _ -> ()
      | Ok doc ->
        let svcs = seq (member "services" doc) in
        let looks_like_deck =
          member "_format_version" doc <> None || svcs <> []
        in
        if not looks_like_deck then ()
        else begin
          incr deck_files;
          List.iter
            (fun sv ->
              incr services;
              (* upstream port, for admin-API recognition *)
              (match member "url" sv with
               | Some (`String u) ->
                 let after =
                   match String.index_opt u ':' with
                   | Some i when i + 3 <= String.length u && String.sub u i 3 = "://" ->
                     String.sub u (i + 3) (String.length u - i - 3)
                   | _ -> u
                 in
                 let auth =
                   match String.index_opt after '/' with
                   | Some i -> String.sub after 0 i
                   | None -> after
                 in
                 (match String.rindex_opt auth ':' with
                  | Some i ->
                    let p = String.sub auth (i + 1) (String.length auth - i - 1) in
                    bump ports p;
                    if p = "8001" || p = "8444" then incr admin_upstreams
                  | None -> ())
               | _ -> ());
              List.iter
                (fun (p : Yaml.value) ->
                  match member "name" p with
                  | Some (`String n) ->
                    bump plugins n;
                    if not (known_plugin n) then bump unknown_plugins n
                  | _ -> ())
                (seq (member "plugins" sv));
              List.iter
                (fun rt ->
                  incr routes;
                  if str_seq (member "hosts" rt) <> [] then incr with_hosts;
                  if member "headers" rt <> None then incr with_headers;
                  if str_seq (member "snis" rt) <> [] then incr with_snis;
                  if str_seq (member "methods" rt) <> [] then incr with_methods;
                  if member "regex_priority" rt <> None then incr regex_priority_set;
                  List.iter
                    (fun (p : Yaml.value) ->
                      match member "name" p with
                      | Some (`String n) ->
                        bump plugins n;
                        if not (known_plugin n) then bump unknown_plugins n
                      | _ -> ())
                    (seq (member "plugins" rt));
                  List.iter
                    (fun path ->
                      incr paths_total;
                      if not (Fragment.is_regex_path path) then incr paths_literal
                      else begin
                        if String.length path > 0 && path.[0] = '~' then
                          incr regex_explicit
                        else incr regex_implicit;
                        match Regex.parse (Fragment.pattern_of path) with
                        | Ok _ -> incr regex_supported
                        | Error why ->
                          (* group by construct, not by the specific pattern *)
                          let key =
                            match String.index_opt why ' ' with
                            | Some i -> String.sub why 0 i
                            | None -> why
                          in
                          bump rejected (key ^ " …")
                      end)
                    (str_seq (member "paths" rt)))
                (seq (member "routes" sv)))
            svcs
        end)
    files;

  let pct n d = if d = 0 then 0.0 else 100.0 *. float_of_int n /. float_of_int d in
  Printf.printf "scanned %d YAML files, %d look like decK configs\n" (List.length files)
    !deck_files;
  Printf.printf "  services %d, routes %d, route paths %d\n\n" !services !routes
    !paths_total;

  Printf.printf "PATHS\n";
  Printf.printf "  literal prefix      %5d  (%.1f%%)\n" !paths_literal
    (pct !paths_literal !paths_total);
  Printf.printf "  regex, explicit ~   %5d  (%.1f%%)\n" !regex_explicit
    (pct !regex_explicit !paths_total);
  Printf.printf "  regex, implicit     %5d  (%.1f%%)\n" !regex_implicit
    (pct !regex_implicit !paths_total);
  let regex_total = !regex_explicit + !regex_implicit in
  Printf.printf "  of %d regex paths, %d translate (%.1f%%), %d rejected\n"
    regex_total !regex_supported (pct !regex_supported regex_total)
    (regex_total - !regex_supported);
  List.iter (fun (k, v) -> Printf.printf "      rejected: %-28s %d\n" k v)
    (top rejected 10);

  Printf.printf "\nROUTING DIMENSIONS (of %d routes)\n" !routes;
  Printf.printf "  methods   %5d  (%.1f%%)   modelled\n" !with_methods
    (pct !with_methods !routes);
  Printf.printf "  hosts     %5d  (%.1f%%)   modelled\n" !with_hosts
    (pct !with_hosts !routes);
  Printf.printf "  headers   %5d  (%.1f%%)   NOT modelled\n" !with_headers
    (pct !with_headers !routes);
  Printf.printf "  snis      %5d  (%.1f%%)   NOT modelled\n" !with_snis
    (pct !with_snis !routes);
  Printf.printf "  regex_priority set  %d\n" !regex_priority_set;

  Printf.printf "\nUPSTREAMS\n";
  Printf.printf "  services pointing at an admin port (8001/8444): %d\n" !admin_upstreams;
  List.iter (fun (k, v) -> Printf.printf "      port %-8s %d\n" k v) (top ports 8);

  Printf.printf "\nPLUGINS (top 15 of %d distinct)\n" (Hashtbl.length plugins);
  List.iter
    (fun (k, v) ->
      Printf.printf "  %-34s %4d%s\n" k v (if known_plugin k then "  [recognised]" else ""))
    (top plugins 15);
  Printf.printf "\n  UNRECOGNISED plugins (%d distinct) — each is treated as\n\
    \  providing no auth and no rate limit, so a route relying on one is reported\n\
    \  as open. Worth checking for anything security-relevant:\n"
    (Hashtbl.length unknown_plugins);
  List.iter
    (fun (k, v) -> Printf.printf "      %-34s %4d\n" k v)
    (top unknown_plugins 40)
