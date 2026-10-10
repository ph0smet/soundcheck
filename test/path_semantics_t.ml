open Soundcheck_core
open Soundcheck_kong

let config ?version path =
  Option.fold ~none:"" ~some:(fun version -> "_format_version: '" ^ version ^ "'\n") version
  ^ "services: [{name: api, routes: [{name: route, paths: ['" ^ path ^ "']}]}]"

let get_path source =
  match Parse.parse_string source with
  | Ok { Ast.services = [ { routes = [ { paths = [ path ]; _ } ]; _ } ]; _ } -> path
  | Ok _ -> failwith "unexpected parsed path shape"
  | Error error -> failwith error

let () =
  if Path_normalization.migrate_legacy_path "/plain\n" <> "/plain\n"
     || Path_normalization.migrate_legacy_path "/plain\n\n" <> "~/plain\n\n"
  then failwith "legacy PCRE final-LF classification differs";
  (* Kong 3.9.3 modern routers recognize ONLY the '~' marker. The declarative
     loader first migrates explicit 1.1/2.1 documents using migrate_path_280_300.
     These expectations are source-derived, not generated from our encoder. *)
  List.iter
    (fun version ->
      let path = get_path (config ?version "/plain/a+b") in
      if Fragment.is_regex_path path
         || not (Lower.path_matches path "/plain/a+b")
         || Lower.path_matches path "/plain/ab"
      then failwith "modern literal plus must not become a regex")
    [ None; Some "3.0" ];
  List.iter
    (fun version ->
      let path = get_path (config ~version "/plain/a+b") in
      if path <> "~/plain/a+b"
         || not (Lower.path_matches path "/plain/ab")
         || Lower.path_matches path "/plain/a+b"
      then failwith "legacy implicit regex migration changed meaning";
      let normalized = get_path (config ~version "/%61//./b") in
      if normalized <> "/a/b" then failwith "legacy literal normalization missing";
      let escaped = get_path (config ~version "/v/%61[0-9]%2e%2f") in
      if escaped <> "~/v/a[0-9]\\.%2F" then
        failwith ("legacy regex percent migration: " ^ escaped))
    [ "1.1"; "2.1" ];
  (match Parse.parse_string
      "_format_version: '2.1'\nservices: [{name: api}]\nroutes: [{name: top, service: api, paths: ['/v/[0-9]+']}]"
   with
   | Ok { Ast.services = [ { routes = [ { paths = [ "~/v/[0-9]+" ]; _ } ]; _ } ];
          top_level_routes = [ { route = { paths = [ "~/v/[0-9]+" ]; _ }; _ } ]; _ } -> ()
   | _ -> failwith "top-level legacy path migration missing or applied twice");
  (match Verify.run ~property:(Verify.No_anonymous_access "/plain/a+b")
           (config ~version:"3.0" "/plain/a+b") with
   | Ok { Report.result = Report.Violated witness; _ }
       when String.starts_with ~prefix:"/plain/a+b" witness.path -> ()
   | _ -> failwith "modern literal path missed by verification");
  print_endline "versioned path semantics checks passed"
