open Soundcheck_kong

(* Independent shape expectations: Kong OSS 3.9.3's declarative_config.lua
   represents entity collections as arrays of records; entities/routes.lua,
   entities/services.lua, entities/plugins.lua, and typedefs.lua specify the
   field types below. These are parser-boundary tests, not a claim to perform
   all of Kong's deployment/schema validation. *)

let failures = ref []

let reject label source =
  match Parse.parse_string source with
  | Error _ -> ()
  | Ok _ -> failures := (label ^ ": malformed input was accepted") :: !failures

let accept label source =
  match Parse.parse_string source with
  | Ok config -> Some config
  | Error error ->
    failures := (label ^ ": " ^ error) :: !failures;
    None

let route field = "services: [{name: api, routes: [{name: admin, " ^ field ^ "}]}]"
let service field = "services: [{name: api, " ^ field ^ "}]"
let plugin field = "plugins: [{" ^ field ^ "}]"

let priority label source expected =
  match accept label (route ("regex_priority: " ^ source)) with
  | Some { services = [ { routes = [ route ]; _ } ]; _ }
    when route.regex_priority = expected -> ()
  | None -> ()
  | Some _ -> failures := (label ^ ": priority changed") :: !failures

let service_name label source expected =
  match accept label source with
  | Some { services = [ service ]; _ } when service.name = expected -> ()
  | None -> ()
  | Some _ -> failures := (label ^ ": service name changed") :: !failures

let () =
  List.iter (fun (label, source) -> reject label source)
    [ ("scalar document", "not-a-config");
      ("sequence document", "[]");
      ("null document", "null");
      ("empty document", "");
      ("second document", "services: []\n---\nservices: []\n");
      ("trailing malformed YAML", "services: []\n...\n[\n");
      ("explicit tag", "plugins: [{name: key-auth, enabled: !!str false}]");
      ("inline merge", "services: []\n<<: {plugins: [{name: key-auth}]}\n");
      ("YAML alias", "services: &services []\nroutes: *services\n");
      ("numeric format version", "_format_version: 3.0\nservices: []\n");
      ("unknown format version", "_format_version: '4.0'\nservices: []\n");
      ("duplicate root key", "services: []\nservices: [{name: api}]\n");
      ("duplicate service field", "services: [{name: api, name: other}]");
      ("duplicate route field", route "paths: [/admin], paths: [/public]");
      ("duplicate header field", route "headers: {x-role: [admin], x-role: [public]}");
      ("boolean mapping key", route "headers: {on: [admin]}");
      ("numeric mapping key", route "headers: {010: [admin]}");
      ("duplicate plugin field", plugin "name: key-auth, enabled: true, enabled: false");
      ("duplicate nested config field", plugin "name: key-auth, config: {run_on_preflight: true, run_on_preflight: false}");
      ("duplicate ignored field", "_ignore: [{nested: {key: 1, key: 2}}]");
      ("services scalar", "services: api");
      ("services object", "services: {name: api}");
      ("service non-object", "services: [api]");
      ("service null member", "services: [null]");
      ("service non-string name", "services: [{name: 17}]");
      ("service non-string URL", service "url: true");
      ("service non-string protocol", service "protocol: []");
      ("service non-string host", service "host: 12");
      ("service null host", service "host: null");
      ("service null protocol", service "protocol: null");
      ("service non-string path", service "path: {} ");
      ("routes object", service "routes: {name: admin}");
      ("route non-object", service "routes: [admin]");
      ("root routes object", "routes: {name: admin}");
      ("root route null", "routes: [null]");
      ("route non-string name", "routes: [{name: false}]");
      ("paths scalar", route "paths: /admin");
      ("paths partial array", route "paths: [/admin, 1]");
      ("methods scalar", route "methods: GET");
      ("methods partial array", route "methods: [GET, false]");
      ("protocols scalar", route "protocols: https");
      ("protocols partial array", route "protocols: [https, null]");
      ("protocols null", route "protocols: null");
      ("hosts scalar", route "hosts: api.example");
      ("snis partial array", route "snis: [api.example, {}]");
      ("headers scalar", route "headers: x-role");
      ("header values scalar", route "headers: {x-role: admin}");
      ("header values partial array", route "headers: {x-role: [admin, true]}");
      ("header values null", route "headers: {x-role: null}");
      ("sources object", route "sources: {ip: 10.0.0.1}");
      ("sources non-record member", route "sources: [10.0.0.1]");
      ("source invalid port", route "sources: [{port: 65536}]");
      ("empty source", route "sources: [{}]");
      ("destinations partial array", route "destinations: [{ip: 10.0.0.1}, false]");
      ("fractional priority", route "regex_priority: 1.5");
      ("quoted priority", route "regex_priority: '12'");
      ("non-numeric priority", route "regex_priority: high");
      ("NaN priority", route "regex_priority: .nan");
      ("infinite priority", route "regex_priority: .inf");
      ("overflow priority", route "regex_priority: 1e100");
      ("integer upper boundary overflow", route "regex_priority: 4611686018427387904");
      ("integer lower boundary overflow", route "regex_priority: -4611686018427389952");
      ("negative port", service "port: -1");
      ("port above schema maximum", service "port: 65536");
      ("fractional port", service "port: 8000.5");
      ("quoted port", service "port: '8000'");
      ("boolean port", service "port: false");
      ("null port", service "port: null");
      ("strip_path string", route "strip_path: 'false'");
      ("strip_path null", route "strip_path: null");
      ("path_handling non-string", route "path_handling: 0");
      ("root plugins scalar", "plugins: key-auth");
      ("service plugins object", service "plugins: {name: key-auth}");
      ("route plugins partial array", route "plugins: [{name: key-auth}, false]");
      ("plugin non-object", "plugins: [key-auth]");
      ("plugin null", "plugins: [null]");
      ("plugin missing name", plugin "enabled: true");
      ("plugin non-string name", plugin "name: 42");
      ("plugin empty name", plugin "name: ''");
      ("plugin string enabled", plugin "name: key-auth, enabled: 'false'");
      ("plugin null enabled", plugin "name: key-auth, enabled: null");
      ("single-letter y is not a boolean", plugin "name: key-auth, enabled: y");
      ("single-letter Y is not a boolean", plugin "name: key-auth, enabled: Y");
      ("single-letter n is not a boolean", plugin "name: key-auth, enabled: n");
      ("single-letter N is not a boolean", plugin "name: key-auth, enabled: N");
      ("plugin config non-record", plugin "name: key-auth, config: []");
      ("plugin config string", plugin "name: key-auth, config: strict");
      ("plugin config null", plugin "name: key-auth, config: null");
      ("preflight non-boolean", plugin "name: key-auth, config: {run_on_preflight: 'false'}");
      ("anonymous non-string", plugin "name: key-auth, config: {anonymous: false}");
      ("IP allow scalar", plugin "name: ip-restriction, config: {allow: 10.0.0.0/8}");
      ("IP deny mixed array", plugin "name: ip-restriction, config: {deny: [10.0.0.0/8, 1]}");
      ("termination trigger non-string", plugin "name: request-termination, config: {trigger: false}") ];

  ignore (accept "empty object remains an empty policy" "{}");
  ignore (accept "trailing comments" "services: []\n...\n# end of one document\n");
  List.iter
    (fun version -> ignore (accept "known format version" ("_format_version: '" ^ version ^ "'\nservices: []\n")))
    [ "1.1"; "2.1"; "3.0" ];
  ignore (accept "null optional collections" "services: null\nroutes: null\nplugins: null\n");
  ignore
    (accept "unrelated entities and fields"
       "_format_version: '3.0'\nconsumers: [{username: test, keyauth_credentials: [{key: test-only}]}]\nservices: [{name: api, tags: [test], retries: 3, routes: [{paths: [/admin]}]}]\n");
  ignore
    (accept "unknown plugin settings are not guessed"
       (plugin "name: custom-plugin, config: {allow: true, anonymous: [custom]}") );
  ignore
    (accept "optional route fields can be null"
       (route "paths: null, methods: null, hosts: null, snis: null, headers: null, sources: null, destinations: null, plugins: null"));
  ignore
    (accept "optional names and service path can be null"
       "services: [{name: null, path: null, routes: [{name: null, paths: [/admin]}]}]");
  ignore
    (accept "well-formed unsupported routing remains parseable"
       (route "sources: [{ip: 10.0.0.0/8}, {port: 443}], destinations: [{ip: '2001:db8::1', port: 443}]"));
  ignore (accept "port lower boundary" (service "port: 0"));
  ignore (accept "port upper boundary" (service "port: 65535"));
  ignore (accept "plain single-letter and quoted boolean header names"
            (route "headers: {y: [admin], 'on': [admin]}"));
  (* Kong 3.9.3 pins LYAML 6.2.8. Its implicit.octal runs before decimal;
     its boolean table does not include single-letter y/Y/n/N. Numeric
     expectations here come from that independent resolver, not Yaml.of_string.
     https://github.com/gvvaughan/lyaml/blob/v6.2.8/lib/lyaml/implicit.lua *)
  List.iter
    (fun (source, expected) -> priority ("LYAML numeric " ^ source) source expected)
    [ ("010", 8); ("+010", 8); ("-010", -8); ("018", 18);
      ("0x10", 16); ("-0x2A", -42); ("1e2", 100); ("1.e+2", 100);
      ("0.1e3", 100); ("-.1e1", -1); ("1.", 1);
      (string_of_int min_int, min_int) ];
  List.iter
    (fun name ->
      service_name ("LYAML plain string " ^ name)
        ("services: [{name: " ^ name ^ "}]") name)
    [ "y"; "Y"; "n"; "N"; "0o10"; "12_abc"; "version1e2" ];
  List.iter
    (fun name ->
      service_name ("quoted scalar remains a string " ^ name)
        ("services: [{name: '" ^ name ^ "'}]") name)
    [ "010"; "0x10"; "0b10"; "1:30"; "1e2"; "_100"; "null"; "yes" ];
  service_name "literal block remains a string" "services:\n- name: |-\n    010\n" "010";
  service_name "folded block remains a string" "services:\n- name: >-\n    yes\n" "yes";
  List.iter
    (fun (source, expected) ->
      match accept ("LYAML boolean " ^ source) (plugin ("name: key-auth, enabled: " ^ source)) with
      | Some { global_plugins = [ plugin ]; _ } when plugin.enabled = expected -> ()
      | None -> ()
      | Some _ -> failures := ("boolean changed: " ^ source) :: !failures)
    [ ("true", true); ("True", true); ("TRUE", true);
      ("yes", true); ("Yes", true); ("YES", true);
      ("on", true); ("On", true); ("ON", true);
      ("false", false); ("False", false); ("FALSE", false);
      ("no", false); ("No", false); ("NO", false);
      ("off", false); ("Off", false); ("OFF", false) ];
  List.iter
    (fun value ->
      reject ("unsupported plain numeric priority " ^ value) (route ("regex_priority: " ^ value));
      reject ("unsupported plain numeric string " ^ value) ("services: [{name: " ^ value ^ "}]"))
    [ "0b10"; "1:30"; "1:30.5"; "1_000"; "_010"; "0_10"; "1_e2";
      "0X1E2"; "0x1.ep2" ];
  (match
     Verify.run ~property:(Verify.No_anonymous_access "/admin")
       "services: [{name: api, routes: [{name: protected, paths: ['~/admin'], regex_priority: 010, plugins: [{name: key-auth}]}, {name: open, paths: ['~/admin'], regex_priority: 9}]}]"
   with
   | Ok { result = Soundcheck_core.Report.Violated _; _ } -> ()
   | _ -> failures := "octal priority must not reverse routing into a proof" :: !failures);
  (match accept "integral priority remains exact" (route "regex_priority: -123.0") with
   | Some { services = [ { routes = [ route ]; _ } ]; _ }
     when route.regex_priority = -123 -> ()
   | None -> ()
   | Some _ -> failures := "integral priority was changed" :: !failures);
  (match
     accept "typed defaults and explicit fields"
       (route "paths: [/admin], strip_path: false, plugins: [{name: key-auth, enabled: false, config: {anonymous: null, run_on_preflight: false}}]")
   with
   | Some { services = [ { routes = [ route ]; _ } ]; _ }
     when not route.strip_path && route.protocols = [ "http"; "https" ]
          && route.path_handling = "v0" && route.regex_priority = 0 ->
     (match route.plugins with
      | [ plugin ] when not plugin.enabled && not plugin.anonymous_fallback
                        && not plugin.run_on_preflight -> ()
      | _ -> failures := "typed plugin fields were changed" :: !failures)
   | None -> ()
   | Some _ -> failures := "typed route fields or defaults were changed" :: !failures);
  (match Parse.parse_string "plugins: [{name: key-auth, service: {id: opaque}}]" with
   | Ok config ->
     (match Fragment.check config with
      | Error _ -> ()
      | Ok () -> failures := "unsupported reference was silently accepted" :: !failures)
   | Error error -> failures := ("unsupported reference changed into parse failure: " ^ error) :: !failures);
  (match Verify.run ~property:(Verify.No_anonymous_access "/admin")
           (route "paths: [/admin], plugins: [{name: key-auth, enabled: 'false'}]") with
   | Error _ -> ()
   | Ok _ -> failures := "malformed input reached a solver verdict" :: !failures);
  if !failures <> [] then begin
    List.iter prerr_endline (List.rev !failures);
    failwith (Printf.sprintf "%d parser checks failed" (List.length !failures))
  end;
  print_endline "strict Kong parser boundary checks passed"
