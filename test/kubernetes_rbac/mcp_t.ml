open Soundcheck_core
module K = Soundcheck_kubernetes_rbac
module M = Soundcheck_mcp.Rbac_server
module I = K.Input

let checks = ref 0
let check label condition = incr checks; if not condition then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let read path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
      really_input_string channel (in_channel_length channel))
let write path contents =
  let channel = open_out_bin path in
  Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () ->
      output_string channel contents; close_out channel)
let field key = function
  | `O fields -> (match List.assoc_opt key fields with
      | Some value -> value | None -> failwith ("missing field " ^ key))
  | _ -> failwith ("not an object: " ^ key)
let optional key = function `O fields -> List.assoc_opt key fields | _ -> None
let string key value = I.str key (field key value)
let array key value = I.arr key (field key value)
let contains text fragment =
  let rec loop offset =
    offset + String.length fragment <= String.length text
    && (String.sub text offset (String.length fragment) = fragment || loop (offset + 1)) in
  loop 0

(* An accidental solver invocation while handling a notification or rejecting
   protocol input is observable, even if the adapter suppresses its response. *)
let () =
  if Array.length Sys.argv > 1 && Sys.argv.(1) = "-smt2" then begin
    write (Sys.getenv "SOUNDCHECK_MCP_TEST_SOLVER_LOG") "solver was invoked\n";
    print_endline "unknown";
    exit 0
  end

let rec cleanup path = match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR ->
    Array.iter (fun name -> cleanup (Filename.concat path name)) (Sys.readdir path);
    Unix.rmdir path
  | _ -> Unix.unlink path

let with_solver_trap directory action =
  let bin = Filename.concat directory "trap-bin" in
  Unix.mkdir bin 0o700;
  Unix.symlink (Unix.realpath Sys.executable_name) (Filename.concat bin "z3");
  let log = Filename.concat bin "calls" in
  let settings = ["PATH",bin ^ ":" ^ Sys.getenv "PATH";
                  "SOUNDCHECK_MCP_TEST_SOLVER_LOG",log] in
  let previous = List.map (fun (key,_) -> key,Sys.getenv_opt key) settings in
  Fun.protect
    ~finally:(fun () -> List.iter (fun (key,value) ->
        Unix.putenv key (Option.value ~default:"" value)) previous)
    (fun () ->
      List.iter (fun (key,value) -> Unix.putenv key value) settings;
      action ();
      check "protocol rejection and notifications never invoke verification"
        (not (Sys.file_exists log)))

let request ?(params=`O []) id method_ =
  I.json (`O ["jsonrpc",`String "2.0";"id",id;
              "method",`String method_;"params",params])
let notification ?(params=`O []) method_ =
  I.json (`O ["jsonrpc",`String "2.0";"method",`String method_;"params",params])
let initialize id = request id "initialize" ~params:(`O [
    "protocolVersion",`String "2024-11-05";"capabilities",`O [];
    "clientInfo",`O ["name",`String "soundcheck-acceptance";"version",`String "1"]])
let arguments config = `O ["config",`String config]
let call ?(metadata=[]) id name config =
  request id "tools/call" ~params:(`O
      (["name",`String name;"arguments",arguments config] @ metadata))
let response state line = match M.handle_line state line with
  | Some line -> I.parse line | None -> failwith "missing JSON-RPC response"
let assert_envelope response =
  check "response is JSON-RPC 2.0" (field "jsonrpc" response = `String "2.0");
  check "response has exactly result or error"
    (Option.is_some (optional "result" response) <> Option.is_some (optional "error" response))
let assert_error ?id code response =
  assert_envelope response;
  check ("JSON-RPC error " ^ string_of_int code)
    (field "code" (field "error" response) = `Number (string_of_int code));
  check "protocol error does not carry a successful result" (optional "result" response = None);
  Option.iter (fun expected -> check "error response ID" (field "id" response = expected)) id
let assert_result id response =
  assert_envelope response;
  check "response preserves request ID exactly" (field "id" response = id);
  field "result" response
let assert_initialize id response =
  let result = assert_result id response in
  check "supported MCP version" (string "protocolVersion" result = "2024-11-05");
  check "tool capability advertised" (field "tools" (field "capabilities" result) = `O [])
let prepare state =
  assert_initialize (`Number "1") (response state (initialize (`Number "1")));
  check "initialized notification has no response"
    (M.handle_line state (notification "notifications/initialized") = None)

let discovery ?baseline expected result =
  let tools = array "tools" result in
  check "only the startup-selected tools are advertised"
    (List.map (string "name") tools = expected);
  List.iter (fun tool ->
      let schema = field "inputSchema" tool in
      check "frozen tool schema is config-only"
        (field "type" schema = `String "object"
         && field "required" schema = `A [`String "config"]
         && field "additionalProperties" schema = `Bool false
         && match field "properties" schema with
            | `O ["config",value] -> field "type" value = `String "string"
            | _ -> false)) tools;
  Option.iter (fun source ->
      let compare = List.find (fun tool -> string "name" tool = "compare") tools in
      check "discovery identifies the captured baseline bytes"
        (contains (string "description" compare) (Sha256.string source))) baseline

let tool_report id response =
  let result = assert_result id response in
  check "verification outcomes are normal tool results"
    (optional "isError" result = None || optional "isError" result = Some (`Bool false));
  let report = field "structuredContent" result in
  let text = match array "content" result with
    | [item] when field "type" item = `String "text" -> string "text" item
    | _ -> failwith "tool report must have one JSON text content item" in
  check "structuredContent exactly matches the serialized report" (I.parse text = report);
  report,text

let assert_report spec outcome report =
  check "report schema 10 is unchanged" (field "schema_version" report = `Number "10");
  check "verification verdict" (string "result" report = outcome);
  let frozen = field "frozen_spec" report in
  check "full canonical contract, identities, groups and change scope stay frozen"
    (string "canonical" frozen = K.Contract_spec.canonical spec
     && string "kind" frozen = "kubernetes-rbac-access"
     && field "schema_version" frozen = `Number "1");
  check "bounded RBAC assurance profile stays fixed"
    (string "profile" (field "assurance" report) = K.Assurance.profile_id)

let assert_witness spec ~before ~after report =
  if string "result" report = "violated" then begin
    let witness = field "counterexample" report in
    let coordinates = field "object_request" witness in
    let object_request : Ir.object_request =
      {namespace=string "namespace" coordinates;resource_kind=string "resource_kind" coordinates;
       name=string "name" coordinates} in
    check "typed named request is retained"
      (string "action" witness = "get" && K.Input.dns_subdomain object_request.name);
    let principal = string "principal" witness in
    let identity = List.find (fun (identity : K.Identity.identity) -> identity.username=principal)
        (K.Contract_spec.identities spec) in
    check "witness groups come from the frozen context"
      (field "identity_groups" witness = `A (List.map (fun s -> `String s) identity.groups));
    let request : Ir.request =
      {principal=Authenticated principal;action="get";resource="";context=[];source=0l;
       host="";scheme="";sni="";object_request=Some object_request} in
    let policy source = K.Lower.policy spec (ok (K.Snapshot.of_string source)) in
    let candidate = policy after in
    let clause = field "clause" report in
    let holds = if string "kind" clause = "must_preserve" then
        Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes spec))
          (policy (Option.get before)) candidate request
      else
        let named = List.find (fun clause_ -> Contract.name clause_=string "name" clause)
            (K.Contract_spec.to_contract spec).clauses in
        Witness.clause candidate named request in
    check "adapter returns a witness satisfying its actual obligation" holds;
    check "granting-rule provenance is not changed by MCP"
      (field "granting_rules" witness
       = `A (List.map (fun s -> `String s) (K.Lower.granting_rules candidate request)))
  end

(* Solver-selected object names need not be stable across CLI/MCP invocations.
   Validate each witness, then compare the remaining complete report identity. *)
let stable_report = function
  | `O fields -> `O (List.filter_map (fun (key,value) ->
      if key="counterexample" then None
      else if key="clause" && optional "kind" value=Some (`String "must_preserve") then
        Some (key,`O ["name",field "name" value;"kind",field "kind" value])
      else Some (key,value)) fields)
  | _ -> failwith "report must be an object"

let direct_checks directory spec baseline repaired unsafe =
  let state = ok (M.create ~contract:spec ~baseline ()) in
  with_solver_trap directory (fun () ->
    assert_error (-32602) (response state (request (`Number "0") "tools/list"));
    assert_error (-32602) (response state (request (`Number "0") "initialize"));
    assert_initialize (`Number "1") (response state (initialize (`Number "1") ^ " "));
    assert_error (-32602) (response state (request (`Number "2") "tools/list"));
    check "tool notifications do not execute before readiness"
      (M.handle_line state (notification "tools/call"
        ~params:(`O ["name",`String "verify";"arguments",arguments unsafe])) = None);
    check "initialized notification is silent"
      (M.handle_line state (notification "notifications/initialized") = None);
    discovery ~baseline ["verify";"compare"]
      (assert_result (`Number "3") (response state (request (`Number "3") "tools/list")));
    assert_error (-32602) (response state (initialize (`Number "4")));
    check "tool notifications never execute verification"
      (M.handle_line state (notification "tools/call"
        ~params:(`O ["name",`String "compare";"arguments",arguments repaired])) = None);
    let id = `Number "900719925474099312345678901234567890" in
    check "large integer ID is never rounded"
      (assert_result id (response state (request id "ping")) = `O []);
    let id = `String "escaped\"\\\n\000identifier" in
    check "escaped string ID round-trips"
      (assert_result id (response state (request id "ping")) = `O []);
    let id = `Number "10" in
    List.iter (fun name ->
      List.iter (fun key ->
        let params = `O ["name",`String name;
          "arguments",`O ["config",`String repaired;key,`String "attempted override"]] in
        assert_error ~id (-32602) (response state (request id "tools/call" ~params)))
        ["contract";"baseline";"connector";"identities";"groups";"subject";"scope";
         "change_scope";"solver";"z3";"output";"evidence_dir";"property";"_meta"])
      ["verify";"compare"];
    List.iter (fun params -> assert_error ~id (-32602)
        (response state (request id "tools/call" ~params)))
      [`O ["name",`String "verify"];
       `O ["name",`String "verify";"arguments",`O []];
       `O ["name",`String "verify";"arguments",`O ["config",`Null]];
       `O ["name",`String "verify";"arguments",`A []];
       `O ["name",`String "verify";"arguments",arguments repaired;"baseline",`String baseline];
       `O ["name",`String "verify";"arguments",arguments repaired;"_meta",`String "override"];
       `O ["name",`String "missing";"arguments",arguments repaired];
       `O ["name",`Number "1";"arguments",arguments repaired];`Null];
    assert_error (-32601) (response state (request id "not-a-method"));
    let duplicate_config escaped =
      {|{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"verify","arguments":{"config":|}
      ^ I.json_string repaired ^ ",\"" ^ escaped ^ "\":" ^ I.json_string unsafe ^ "}}}" in
    List.iter (fun source -> assert_error ~id:`Null (-32700) (response state source))
      [duplicate_config "config";duplicate_config "confi\\u0067";
       {|{"jsonrpc":"2.0","id":10,"method":"ping","metho\u0064":"tools/call"}|};
       request id "ping" ^ "{}";
       {|{jsonrpc: "2.0", id: 10, method: ping}|};
       {|{"jsonrpc":"2.0","id":"|} ^ "\xff" ^ {|","method":"ping"}|};
       {|{"jsonrpc":"2.0","id":"\ud800","method":"ping"}|};
       request id "ping" ^ "\000";
       String.make (M.max_message_bytes + 1) ' '];
    List.iter (fun bad_id -> assert_error ~id:`Null (-32600)
        (response state (request bad_id "ping"))) [`Null;`Bool true;`Number "1.5";`O []];
    List.iter (fun source -> assert_error (-32600) (response state source))
      [{|{"id":10,"method":"ping"}|};
       {|{"jsonrpc":"1.0","id":10,"method":"ping"}|};
       {|{"jsonrpc":"2.0","id":10,"method":42}|};
       {|{"jsonrpc":"2.0","id":10,"method":"ping","result":{}}|};"[]"]);
  let state = ok (M.create ~contract:spec ()) in
  prepare state;
  discovery ["verify"] (assert_result (`Number "2")
      (response state (request (`Number "2") "tools/list")));
  assert_error (-32602) (response state (call (`Number "3") "compare" repaired));
  let report,_ = tool_report (`Number "4") (response state
      (call (`Number "4") "verify" unsafe ~metadata:["_meta",`O [
        "progressToken",`String "progress";"contract",`String "{}";
        "baseline",`String repaired;"groups",`A []]])) in
  assert_report spec "violated" report;
  check "protocol metadata cannot weaken access requirements"
    (string "kind" (field "clause" report) = "must_not_grant")

let run binary args =
  let stdout_path = Filename.temp_file "rbac-mcp-cli-out-" "" in
  let stderr_path = Filename.temp_file "rbac-mcp-cli-err-" "" in
  Fun.protect ~finally:(fun () -> Sys.remove stdout_path;Sys.remove stderr_path) (fun () ->
    let input = Unix.openfile "/dev/null" [Unix.O_RDONLY] 0 in
    let output = Unix.openfile stdout_path [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let error = Unix.openfile stderr_path [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let pid = Unix.create_process binary (Array.of_list (binary::args)) input output error in
    List.iter Unix.close [input;output;error];
    let _,status = Unix.waitpid [] pid in
    let code = match status with Unix.WEXITED code -> code | _ -> failwith "CLI terminated unexpectedly" in
    code,read stdout_path,read stderr_path)

type child = {
  pid : int; input : out_channel; output : Unix.file_descr; error_path : string;
  mutable pending : string; mutable reaped : bool;
}

let with_child directory binary args action =
  let input_read,input_write = Unix.pipe ~cloexec:true () in
  let output_read,output_write = Unix.pipe ~cloexec:true () in
  let error_path = Filename.temp_file ~temp_dir:directory "mcp-stderr-" "" in
  let error = Unix.openfile error_path [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
  let pid = Unix.create_process binary (Array.of_list (binary::args)) input_read output_write error in
  List.iter Unix.close [input_read;output_write;error];
  let child = {pid;input=Unix.out_channel_of_descr input_write;output=output_read;
               error_path;pending="";reaped=false} in
  Fun.protect ~finally:(fun () ->
    close_out_noerr child.input;
    if not child.reaped then begin
      (try Unix.kill child.pid Sys.sigkill with Unix.Unix_error (Unix.ESRCH,_,_) -> ());
      ignore (Unix.waitpid [] child.pid)
    end;
    Unix.close child.output) (fun () -> action child)

let receive child =
  let deadline = Unix.gettimeofday () +. 45. in
  let rec loop () = match String.index_opt child.pending '\n' with
    | Some offset ->
      let line = String.sub child.pending 0 offset in
      child.pending <- String.sub child.pending (offset+1) (String.length child.pending-offset-1);
      I.parse line
    | None ->
      let timeout = deadline -. Unix.gettimeofday () in
      if timeout <= 0. || (let ready,_,_ = Unix.select [child.output] [] [] timeout in ready=[]) then
        failwith "timed out waiting for MCP response";
      let bytes = Bytes.create 4096 in
      let length = Unix.read child.output bytes 0 (Bytes.length bytes) in
      if length=0 then failwith ("MCP closed stdout unexpectedly: " ^ read child.error_path);
      child.pending <- child.pending ^ Bytes.sub_string bytes 0 length;
      loop () in
  loop ()
let send child source = output_string child.input source;output_char child.input '\n';flush child.input
let exchange child source = send child source;receive child
let finish child =
  close_out child.input;
  check "no unrequested protocol responses are buffered" (child.pending="");
  let ready,_,_ = Unix.select [child.output] [] [] 10. in
  check "server closes stdout after EOF" (ready<>[]);
  let bytes = Bytes.create 1 in
  check "stdout contains only expected complete protocol messages" (Unix.read child.output bytes 0 1=0);
  let _,status = Unix.waitpid [] child.pid in
  child.reaped <- true;
  check "MCP process exits cleanly" (status=Unix.WEXITED 0);
  check "normal MCP startup/requests do not write diagnostics" (read child.error_path="")
let start child =
  assert_initialize (`Number "1") (exchange child (initialize (`Number "1")));
  send child (notification "notifications/initialized")

let process_checks directory binary root spec =
  let fixture name = Filename.concat root ("fixtures/" ^ name ^ ".json") in
  let contract_path = Filename.concat root "contracts/frontend-access.json" in
  let original_contract = read contract_path in
  let baseline_path = fixture "01-unsafe" in
  let baseline = read baseline_path and repaired = read (fixture "03-valid-repair") in
  let regression = read (fixture "16-operator-regression") in
  let snapshots = [
    "verify","03-valid-repair",0,"proved";
    "verify","01-unsafe",3,"violated";
    "verify","02-delete-workload-grants",3,"violated";
    "verify","30-stale-aggregation",4,"unknown";
    "verify","23-nul-verb-literal",3,"violated";
    "compare","03-valid-repair",0,"proved";
    "compare","16-operator-regression",3,"violated"] in
  let expected = List.map (fun (operation,name,code,outcome) ->
      let args = if operation="compare" then ["compare";baseline_path;fixture name]
        else ["verify";fixture name] in
      let actual,stdout,stderr = run binary
          ("rbac"::args @ ["--contract";contract_path;"--format";"json"]) in
      check ("CLI reference exit: " ^ name ^ stderr) (actual=code && stderr="");
      let report=I.parse stdout in
      assert_report spec outcome report;
      assert_witness spec ~before:(if operation="compare" then Some baseline else None)
        ~after:(read (fixture name)) report;
      operation,name,outcome,report) snapshots in
  let copy_contract = Filename.concat directory "contract.json" in
  let copy_baseline = Filename.concat directory "baseline.json" in
  write copy_contract original_contract;write copy_baseline baseline;
  let args = ["mcp";"--connector";"kubernetes-rbac";"--contract";copy_contract] in
  with_child directory binary (args @ ["--baseline";copy_baseline]) (fun child ->
    start child;
    discovery ~baseline ["verify";"compare"]
      (assert_result (`Number "2") (exchange child (request (`Number "2") "tools/list")));
    List.iteri (fun index (operation,name,outcome,expected) ->
        let id=`Number (string_of_int (index+10)) in
        let source=read (fixture name) in
        let report,_=tool_report id (exchange child (call id operation source)) in
        assert_report spec outcome report;
        assert_witness spec ~before:(if operation="compare" then Some baseline else None) ~after:source report;
        check "MCP and CLI preserve all report fields apart from validated solver choices"
          (stable_report report=stable_report expected);
        if name="23-nul-verb-literal" then check "escaped NUL is not truncated into a get grant"
          (string "kind" (field "clause" report)="must_allow")) expected;
    let id=`Number "30" in
    let nul_source=repaired ^ "\000{}" in
    let report,text=tool_report id (exchange child (call id "verify" nul_source)) in
    assert_report spec "unknown" report;
    check "decoded config bytes, including NUL, reach the verifier unchanged"
      (text=Report.to_json (K.Verify.run spec nul_source));
    List.iteri (fun index source ->
        let id=`Number (string_of_int (index+31)) in
        let report,_=tool_report id (exchange child (call id "verify" source)) in
        assert_report spec "unknown" report)
      [repaired ^ "{}";{|{"apiVersion":"v1","kind":"List","items":[],"it\u0065ms":[]}|}];
    (* The initialize response and discovery above are barriers: all startup
       reads have finished before these files are replaced, then removed. *)
    write copy_contract "{}";write copy_baseline regression;
    let check_frozen id name source outcome =
      let report,_=tool_report id (exchange child (call id name source)) in
      assert_report spec outcome report;
      assert_witness spec ~before:(if name="compare" then Some baseline else None) ~after:source report in
    check_frozen (`Number "40") "verify" repaired "proved";
    check_frozen (`Number "41") "compare" regression "violated";
    discovery ~baseline ["verify";"compare"]
      (assert_result (`Number "42") (exchange child (request (`Number "42") "tools/list")));
    Unix.unlink copy_contract;Unix.unlink copy_baseline;
    check_frozen (`Number "43") "compare" repaired "proved";
    check_frozen (`Number "44") "compare" regression "violated";
    check_frozen (`Number "45") "verify" baseline "violated";
    let oversized=call (`Number "50") "verify" repaired ^ String.make M.max_message_bytes ' ' in
    assert_error ~id:`Null (-32700) (exchange child oversized);
    let id=`String "after oversized frame" in
    check "oversized frame is fully drained before the next request"
      (assert_result id (exchange child (request id "ping"))=`O []);
    finish child);
  write copy_contract original_contract;
  with_child directory binary args (fun child ->
    start child;
    discovery ["verify"] (assert_result (`Number "2")
      (exchange child (request (`Number "2") "tools/list")));
    assert_error (-32602) (exchange child (call (`Number "3") "compare" repaired));
    let report,_=tool_report (`Number "4") (exchange child (call (`Number "4") "verify" repaired)) in
    assert_report spec "proved" report;
    finish child)

let startup_checks directory binary root =
  let contract=Filename.concat root "contracts/frontend-access.json" in
  let baseline=Filename.concat root "fixtures/01-unsafe.json" in
  let base=["mcp";"--connector";"kubernetes-rbac";"--contract";contract] in
  let rejected code args =
    let actual,stdout,stderr=run binary args in
    check ("startup rejects invalid options/input: " ^ String.concat " " args)
      (actual=code && stdout="" && stderr<>"") in
  List.iter (rejected 2)
    [["mcp";"--connector";"kubernetes-rbac"];
     ["mcp";"--connector";"other";"--contract";contract];
     ["mcp";"--baseline";baseline];
     base @ ["--connector";"kubernetes-rbac"];
     base @ ["--contract";contract];
     base @ ["--baseline";baseline;"--baseline";baseline];
     base @ ["--baseline"];
     base @ ["--baseline";""];
     base @ ["--solver";"z3"];
     base @ ["--evidence-dir";Filename.concat directory "unwanted-evidence"];
     base @ ["--format";"json"];
     base @ ["--subject";"alice"];
     base @ ["unexpected-positional"]];
  let invalid_contract=Filename.concat directory "bad-contract.json" in
  write invalid_contract (read contract ^ "{}");
  rejected 2 ["mcp";"--connector";"kubernetes-rbac";"--contract";invalid_contract];
  rejected 2 (base @ ["--baseline";Filename.concat root "fixtures/30-stale-aggregation.json"]);
  rejected 1 (base @ ["--baseline";Filename.concat directory "missing-baseline"]);
  rejected 1 ["mcp";"--connector";"kubernetes-rbac";"--contract";Filename.concat directory "missing-contract"];
  check "rejected path arguments cannot create files"
    (not (Sys.file_exists (Filename.concat directory "unwanted-evidence")))

let () =
  if Array.length Sys.argv<>3 then failwith "usage: mcp_t SOUNDCHECK RBAC_BENCH";
  let binary=Sys.argv.(1) and root=Sys.argv.(2) in
  let directory=Filename.temp_file "soundcheck-rbac-mcp-" "" in
  Unix.unlink directory;Unix.mkdir directory 0o700;
  Fun.protect ~finally:(fun () -> cleanup directory) (fun () ->
    let spec=ok (K.Contract_spec.of_string (read (Filename.concat root "contracts/frontend-access.json"))) in
    let source name=read (Filename.concat root ("fixtures/" ^ name ^ ".json")) in
    check "unsupported startup baseline is rejected"
      (Result.is_error (M.create ~contract:spec ~baseline:(source "30-stale-aggregation") ()));
    direct_checks directory spec (source "01-unsafe") (source "03-valid-repair") (source "01-unsafe");
    process_checks directory binary root spec;
    startup_checks directory binary root);
  Printf.printf "RBAC MCP: %d checks passed\n" !checks
