(* MCP adapter smoke test: drive {!Soundcheck_mcp.Server.handle_line} with
   representative JSON-RPC lines and print each response. Exercises dispatch +
   the [verify] tool + the JSON result contract in-process (no subprocess),
   mirroring test/smoke.ml's demonstrator style.

   Configs are written in flow-style YAML (valid on a single line) so they embed
   in the request's JSON [config] string without newline escaping. *)

let requests =
  [ (* handshake *)
    {|{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}|};
    {|{"jsonrpc":"2.0","method":"notifications/initialized"}|};
    (* discovery *)
    {|{"jsonrpc":"2.0","id":2,"method":"tools/list"}|};
    (* insecure: /admin route with no auth -> VIOLATED *)
    {|{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"verify","arguments":{"config":"{services: [{name: admin-api, routes: [{name: admin-route, paths: [/admin]}]}]}"}}}|};
    (* secure: /admin route requires key-auth -> PROVED *)
    {|{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"verify","arguments":{"config":"{services: [{name: admin-api, routes: [{name: admin-route, paths: [/admin], plugins: [{name: key-auth}]}]}]}"}}}|};
    (* paired contract: the same guarded GET route preserves functionality *)
    {|{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"verify","arguments":{"property":"authenticated-access","path_prefix":"/admin","method":"GET","config":"{services: [{name: admin-api, routes: [{name: admin-route, paths: [/admin], methods: [GET], plugins: [{name: key-auth}]}]}]}"}}}|};
  ]

let () =
  List.iter
    (fun line ->
      match Soundcheck_mcp.Server.handle_line line with
      | Some response -> print_endline response
      | None -> () (* notification: no reply *))
    requests
