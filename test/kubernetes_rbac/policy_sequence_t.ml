open Soundcheck_core
module K = Soundcheck_kubernetes_rbac
module S = K.Sequence_spec
module P = K.Policy_sequence
let checks = ref 0
let check name yes = incr checks; if not yes then failwith ("policy sequence: "^name)
let ok = function Ok value -> value | Error reason -> failwith reason
let str x = `String x
let strings xs = `A (List.map str xs)
let json = K.Input.json
let parse = K.Input.parse
let fields = function `O values -> values | _ -> failwith "expected object"
let field name value = List.assoc name (fields value)
let replace name value obj = `O (List.map (fun (k,v) -> k,if k=name then value else v) (fields obj))
let add name value obj = `O (fields obj @ [name,value])
let remove name obj = `O (List.filter (fun (k,_) -> k<>name) (fields obj))
let rr ?(group="") ?(verbs=["get"]) ?(names=[]) resources = `O ["apiGroups",strings [group];
  "resources",strings resources;"verbs",strings verbs;"resourceNames",strings names]
let role ?(namespace="apps") ?(kind="Role") name rules = `O ["apiVersion",str K.Input.api_version;
  "kind",str kind;"metadata",`O ["name",str name;"namespace",str namespace];"rules",`A rules]
let binding ?(namespace="apps") ?(kind="RoleBinding") ?(role_kind="Role") name reference subjects =
  `O ["apiVersion",str K.Input.api_version;"kind",str kind;
    "metadata",`O ["name",str name;"namespace",str namespace];
    "subjects",`A (List.map (fun name -> `O ["kind",str "User";"apiGroup",str K.Input.group;"name",str name]) subjects);
    "roleRef",`O ["apiGroup",str K.Input.group;"kind",str role_kind;"name",str reference]]
let source items = json (`O ["apiVersion",str "v1";"kind",str "List";"items",`A items])
let scope resource names = ["subject",str "workload";"namespace",str "apps";"resource",str resource;"names",strings names]
let requirements = `O ["schema_version",`Number "1";"kind",str K.Contract_spec.kind;
  "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
    "identities",`A (List.map (fun name -> `O ["username",str name;"groups",`A []]) ["deployer";"workload";"observer"])];
  "clauses",`A [`O (["name",str "read-config";"kind",str "must_allow"] @ scope "configmaps" ["app"]);
    `O (["name",str "keep-secret-private";"kind",str "must_not_grant"] @ scope "secrets" ["db"])];
  "change_scope",`A [`O (scope "secrets" ["db"])]]
let step ?(kind="Role") ?(namespace=`String "apps") ?(operation="update-existing") name =
  `O ["operation",str operation;"target",`O ["kind",str kind;"namespace",namespace;"name",str name]]
let contract steps = `O ["schema_version",`Number "1";"kind",str S.kind;"actor",str "deployer";
  "steps",`A steps;"requirements",requirements]
let spec steps = S.of_string (json (contract steps)) |> ok
let config_rule=rr ~names:["app"] ["configmaps"]
let other_config_rule=rr ~names:["other"] ["configmaps"]
let secret_rule=rr ~names:["db"] ["secrets"]
let privilege ?(verbs=["create";"update";"escalate";"bind"]) resources = rr ~group:K.Input.group ~verbs resources
let admin = [role ~namespace:"" ~kind:"ClusterRole" "authority"
    [privilege ["roles";"rolebindings";"clusterroles";"clusterrolebindings"]];
  binding ~namespace:"" ~kind:"ClusterRoleBinding" ~role_kind:"ClusterRole" "authority" "authority" ["deployer"]]
let binds = [binding "a" "a" ["workload"];binding "b" "b" ["workload"]]
let before_items = admin @ [role "a" [config_rule;other_config_rule;secret_rule];role "b" [secret_rule]] @ binds
let after_items = admin @ [role "a" [config_rule;other_config_rule];role "b" []] @ binds
let before=source before_items
let after=source after_items
let frozen=spec [step "a";step "b"]
let run ?z3 ?(spec=frozen) ?(before=before) after = P.run ?z3 spec ~before ~after
let coherent name t = check (name^" coherent") (P.validate_evaluation t=Ok ())
let outcome name expected t =
  check (name^"\n"^P.to_human t) ((P.evaluation t).outcome=expected);coherent name t
let error name value = check name (Result.is_error (S.of_string (json value)))
let provenance : Evidence.provenance = {executable_sha256=String.make 64 'a';ocaml_version="test";z3_version=Ok "test"}
let check_evidence name t =
  let files=P.evidence_files provenance t |> ok in
  let manifest=List.assoc "manifest.json" files |> parse in
  let artifacts=field "artifacts" manifest |> function `A xs -> xs | _ -> assert false in
  check (name^" all artifacts") (List.length artifacts=List.length files-1);
  List.iter (fun value ->
    let path=field "path" value |> function `String s -> s | _ -> assert false in
    let content=List.assoc path files in
    check (name^" artifact digest "^path) (field "sha256" value=str (Sha256.string content));
    check (name^" artifact bytes "^path) (field "bytes" value=`Number (string_of_int (String.length content)))) artifacts;
  files

(* A protocol-valid SAT response for an unchanged request must be rejected by
   the preservation-only helper's semantic witness check. *)
let () =
  if Array.length Sys.argv>=2 && Sys.argv.(1)="-version" then begin
    print_endline "Z3 version sequence-invalid-witness-fixture";exit 0
  end;
  if Array.length Sys.argv>=3 && Sys.argv.(1)="-smt2" then begin
    let channel=open_in_bin Sys.argv.(2) in
    let text=really_input_string channel (in_channel_length channel) in
    close_in channel;
    print_endline "sat";
    let fragment="(get-value" in
    let rec contains i = i+String.length fragment<=String.length text &&
      (String.sub text i (String.length fragment)=fragment || contains (i+1)) in
    if contains 0 then print_endline
      "((path \"\") (method \"get\") (is_anon false) (src_ip #x00000000) (host \"\") (scheme \"\") (sni \"\") (principal_name \"workload\") (has_object_request true) (object_namespace \"apps\") (object_kind \"configmaps\") (object_name \"app\"))";
    exit 0
  end

let () =
  check "canonical round trip" (S.canonical (S.of_string (S.canonical frozen) |> ok)=S.canonical frozen);
  check "order is frozen" (S.canonical frozen<>S.canonical (spec [step "b";step "a"]));
  check "actor and nested identity retained" ((S.actor frozen).username="deployer" &&
    K.Contract_spec.canonical (S.requirements frozen)=K.Contract_spec.canonical (K.Contract_spec.of_string (json requirements) |> ok));
  check "review states intermediate boundary" (String.length (S.review frozen)>300);
  List.iter (fun (name,value) -> error name value) [
    "empty sequence",contract [];"too many steps",contract (List.init 17 (fun i -> step ("r"^string_of_int i)));
    "duplicate target",contract [step "a";step "a"];
    "duplicate key",add "actor" (str "deployer") (contract [step "a"]);
    "unknown key",add "intermediate_requirements" (`Bool false) (contract [step "a"]);
    "unknown version",replace "schema_version" (`Number "3") (contract [step "a"]);
    "noninteger version",replace "schema_version" (`Number "1.0") (contract [step "a"]);
    "missing requirements",remove "requirements" (contract [step "a"]);
    "unknown actor",replace "actor" (str "other") (contract [step "a"]);
    "step actor override",contract [add "actor" (str "other") (step "a")];
    "step requirement override",contract [add "requirements" requirements (step "a")];
    "step typo",contract [add "operation_order" (`Number "1") (step "a")];
    "patch excluded",contract [step ~operation:"patch" "a"];
    "delete excluded",contract [step ~operation:"delete" "a"];
    "null namespaced target",contract [step ~namespace:`Null "a"];
    "cluster namespace excluded",contract [step ~kind:"ClusterRole" "a"] ];
  check "maximum accepted" (Result.is_ok (S.of_string (json (contract (List.init 16 (fun i -> step ("r"^string_of_int i)))))));
  check "different namespaces distinct" (Result.is_ok (S.of_string (json (contract [step "a";step ~namespace:(str "other") "a"]))));
  let valid=run after in
  outcome "staged repair passes" P.Valid_sequence valid;
  let e=P.evaluation valid in
  check "all ordered authorizations" (e.authorization_allowed=Some true && List.length e.steps=2);
  check "prefix query executed" (List.for_all (fun p -> match p.P.verification with
    | Some {report={result=Report.Proved;_};_} -> true | _ -> false) e.intermediate_preservation);
  let files=check_evidence "valid" valid in
  check "raw endpoints retained" (List.assoc "states/state-000.json" files=before && List.assoc "states/state-002.json" files=after);
  let intermediate=List.assoc "states/state-001.json" files in
  check "final clauses need not hold at prefix" (match K.Verify.run (S.requirements frozen) intermediate with
    | {result=Report.Violated _;_} -> true | _ -> false);
  check "prefix preservation query replay" (Solve.check (List.hd e.intermediate_preservation).query=Solve.Proved);
  let plan=K.Verify.plan_preservation (S.requirements frozen) ~before ~after:intermediate |> ok in
  let fake_z3=if Filename.is_relative Sys.executable_name then Filename.concat (Sys.getcwd ()) Sys.executable_name
    else Sys.executable_name in
  let invalid=K.Verify.execute_preservation ~z3:fake_z3 plan in
  check ("prefix invalid witness fails closed\n"^Report.to_human invalid.report) (match invalid.report.result,invalid.trace.execution with
    | Report.Unknown reason,Contract_verify.Executed (Solve.Unknown same) ->
      reason=same && String.starts_with ~prefix:"solver witness validation failed" reason
    | _ -> false);
  check "final comparison bundle retained" (List.mem_assoc "verification/manifest.json" files);
  let transient=source (admin @ [role "a" [config_rule];role "b" [other_config_rule]] @ binds) in
  let lost=run transient in
  outcome "restored final permission still fails prefix" P.Out_of_scope_regression lost;
  let e=P.evaluation lost in
  check "prefix failure attributed" (e.phase=P.Intermediate_preservation && e.failing_step=Some 1);
  check "final succeeded before prefix failure" (match e.comparison with Some {report={result=Report.Proved;_};_}->true | _->false);
  ignore (check_evidence "prefix failure" lost);
  outcome "reverse order preserves workflow" P.Valid_sequence (run ~spec:(spec [step "b";step "a"]) transient);
  outcome "final required access lost" P.Contract_failed (run (source (admin @ [role "a" [other_config_rule];role "b" []] @ binds)));
  let final_loss=run (source (admin @ [role "a" [config_rule];role "b" []] @ binds)) in
  outcome "final preservation failure" P.Out_of_scope_regression final_loss;
  check "final failure phase" ((P.evaluation final_loss).phase=P.Final_verification);
  let contradictory=replace "clauses" (`A [
    `O (["name",str "allow-secret";"kind",str "must_allow"] @ scope "secrets" ["db"]);
    `O (["name",str "deny-secret";"kind",str "must_not_grant"] @ scope "secrets" ["db"])]) requirements in
  let inconsistent_spec=contract [step "a";step "b"] |> replace "requirements" contradictory |> json |> S.of_string |> ok in
  let inconsistent=run ~spec:inconsistent_spec after in
  outcome "inconsistent final contract is distinct nonproof" P.Contract_failed inconsistent;
  check "inconsistent gate exit" (P.exit_code inconsistent=6);
  check "inconsistent final skips intermediate solvers" (List.for_all (fun p -> p.P.verification=None)
    (P.evaluation inconsistent).intermediate_preservation);
  let unavailable=run ~z3:"/no/such/soundcheck-sequence-z3" after in
  outcome "solver failure unknown" P.Unknown unavailable;
  check "prefix solver not run after final unknown" (List.for_all (fun p -> p.P.verification=None) (P.evaluation unavailable).intermediate_preservation);
  ignore (check_evidence "solver unavailable" unavailable);
  let extra=run (source (after_items @ [role "unapproved" []])) in
  outcome "extra object unknown" P.Unknown extra;
  check "prepare failed before later stages" ((P.evaluation extra).phase=P.Preparation && (P.evaluation extra).steps=[]);
  ignore (check_evidence "preparation failure" extra);
  let noop=run before in
  outcome "no-op unknown" P.Unknown noop;
  check "no-op step attributed" ((P.evaluation noop).failing_step=Some 1);
  outcome "target missing unknown" P.Unknown (run (source (admin @ [role "a" [config_rule;other_config_rule]] @ [binding "a" "a" ["workload"]])));
  let metadata_only=source (List.map (fun obj -> if field "kind" obj=str "Role" &&
    field "name" (field "metadata" obj)=str "a" then
      replace "metadata" (add "labels" (`O ["app",str "new"]) (field "metadata" obj)) obj else obj) before_items) in
  outcome "metadata-only excluded" P.Unknown (run metadata_only);
  (* Each operation sees the grants established by earlier accepted steps. *)
  let manager=role "manager" [privilege ~verbs:["update";"bind"] ["rolebindings";"roles"]] in
  let authority=role "later-authority" [privilege ~verbs:["update";"escalate"] ["roles"]] in
  let base=[manager;binding "manager" "manager" ["deployer"];authority;
    role "a" [config_rule;other_config_rule;secret_rule];binding "a" "a" ["workload"]] in
  let before_grant=source (base @ [binding "later" "later-authority" ["observer"]]) in
  let after_grant=source ([manager;binding "manager" "manager" ["deployer"];authority;
    role "a" [config_rule;other_config_rule];binding "a" "a" ["workload"];
    binding "later" "later-authority" ["deployer"]]) in
  let grant_spec=spec [step ~kind:"RoleBinding" "later";step "a"] in
  outcome "grant then use" P.Valid_sequence (run ~spec:grant_spec ~before:before_grant after_grant);
  (* Manager's update on roles above is intentional; escalate coverage added by
     the prior binding is necessary because proposed access rules are not held. *)
  let reversed=run ~spec:(spec [step "a";step ~kind:"RoleBinding" "later"]) ~before:before_grant after_grant in
  outcome "future authority cannot authorize earlier write" P.Authorization_failed reversed;
  check "failed at first step" ((P.evaluation reversed).failing_step=Some 1);
  let before_revoke=source (base @ [binding "later" "later-authority" ["deployer"]]) in
  let after_revoke=source ([manager;binding "manager" "manager" ["deployer"];authority;
    role "a" [config_rule;other_config_rule];binding "a" "a" ["workload"];
    binding "later" "later-authority" ["observer"]]) in
  let revoked=run ~spec:grant_spec ~before:before_revoke after_revoke in
  outcome "revoked authority unavailable later" P.Authorization_failed revoked;
  check "revocation failure step" ((P.evaluation revoked).failing_step=Some 2);
  ignore (check_evidence "revoked" revoked);
  (* Complete snapshots require role creation before its binding. *)
  let create_spec=spec [step ~operation:"create" "created";step ~kind:"RoleBinding" ~operation:"create" "created"] in
  let before_create=source (admin @ [role "a" [config_rule;other_config_rule];binding "a" "a" ["workload"]]) in
  let after_create=source (admin @ [role "a" [config_rule;other_config_rule];binding "a" "a" ["workload"];
    role "created" [];binding "created" "created" ["workload"]]) in
  outcome "create referenced role before binding" P.Valid_sequence (run ~spec:create_spec ~before:before_create after_create);
  let max_spec=spec (List.init 16 (fun i -> step ~operation:"create" ("max-"^string_of_int i))) in
  let max_before=admin @ [role "a" [config_rule;other_config_rule];binding "a" "a" ["workload"]] in
  let max_after=source (max_before @ List.init 16 (fun i -> role ("max-"^string_of_int i) [])) in
  let max_result=run ~spec:max_spec ~before:(source max_before) max_after in
  outcome "maximum sequence executes all required stages" P.Valid_sequence max_result;
  check "maximum has fifteen intermediate obligations" (List.length (P.evaluation max_result).intermediate_preservation=15);
  let reverse_create=spec [step ~kind:"RoleBinding" ~operation:"create" "created";step ~operation:"create" "created"] in
  let malformed=run ~spec:reverse_create ~before:before_create after_create in
  outcome "binding before role unsupported" P.Unknown malformed;
  check "missing intermediate role detected in preparation" ((P.evaluation malformed).phase=P.Preparation && (P.evaluation malformed).failing_step=Some 1);
  let single_before=source (admin @ [role "a" [config_rule;other_config_rule;secret_rule];binding "a" "a" ["workload"]]) in
  let single_after=source (admin @ [role "a" [config_rule;other_config_rule];binding "a" "a" ["workload"]]) in
  let one=spec [step "a"] in
  let sequence=run ~spec:one ~before:single_before single_after in
  let single=K.Policy_change.run (List.hd (S.steps one)) ~before:single_before ~after:single_after in
  outcome "one step passes" P.Valid_sequence sequence;
  check "one step agrees with existing gate" (K.Policy_change.exit_code single=P.exit_code sequence &&
    (P.evaluation sequence).intermediate_preservation=[] &&
    (P.evaluation sequence).authorization_allowed=(K.Policy_change.evaluation single).authorization_allowed);
  List.iter (fun (label,candidate) ->
    let sequence=run ~spec:one ~before:single_before candidate in
    let single=K.Policy_change.run (List.hd (S.steps one)) ~before:single_before ~after:candidate in
    let expected=match (K.Policy_change.evaluation single).outcome with
      | Valid_change -> P.Valid_sequence | Authorization_failed -> P.Authorization_failed
      | Contract_failed -> P.Contract_failed | Out_of_scope_regression -> P.Out_of_scope_regression
      | Unknown -> P.Unknown in
    outcome ("single-step parity: "^label) expected sequence;
    check ("single-step exit parity: "^label) (P.exit_code sequence=K.Policy_change.exit_code single)) [
      "unsupported no-op",single_before;
      "required access missing",source (admin @ [role "a" [other_config_rule];binding "a" "a" ["workload"]]);
      "preservation loss",source (admin @ [role "a" [config_rule];binding "a" "a" ["workload"]]);
      "extra mutation",source (admin @ [role "a" [config_rule;other_config_rule];role "extra" [];binding "a" "a" ["workload"]]) ];
  coherent "invalid contract" (P.invalid_contract "invalid" ~before ~after);
  check "invalid contract cannot write evidence" (Result.is_error (P.evidence_files provenance (P.invalid_contract "invalid" ~before ~after)));
  Printf.printf "RBAC policy sequence: %d checks passed\n" !checks
