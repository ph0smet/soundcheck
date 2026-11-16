open Soundcheck_core
module K = Soundcheck_kubernetes_rbac
module C = K.Change_spec
module S = K.Sequence_spec
module P = K.Policy_sequence
let count = ref 0
let check name yes = incr count; if not yes then failwith ("policy retirement: "^name)
let ok = function Ok x -> x | Error e -> failwith e
let str x = `String x
let strings xs = `A (List.map str xs)
let json = K.Input.json
let parse = K.Input.parse
let fields = function `O xs -> xs | _ -> failwith "object expected"
let field k x = List.assoc k (fields x)
let replace k v x = `O (List.map (fun (key,value) -> key,if key=k then v else value) (fields x))
let add k v x = `O (fields x @ [k,v])
let rr ?(group="") ?(verbs=["get"]) ?(names=[]) resources = `O ["apiGroups",strings [group];
  "verbs",strings verbs;"resources",strings resources;"resourceNames",strings names]
let role ?(kind="Role") ?(ns="apps") name rules = `O ["apiVersion",str K.Input.api_version;
  "kind",str kind;"metadata",`O ["name",str name;"namespace",str ns];"rules",`A rules]
let binding ?(kind="RoleBinding") ?(ns="apps") ?(role_kind="Role") name reference users =
  `O ["apiVersion",str K.Input.api_version;"kind",str kind;
    "metadata",`O ["name",str name;"namespace",str ns];
    "roleRef",`O ["apiGroup",str K.Input.group;"kind",str role_kind;"name",str reference];
    "subjects",`A (List.map (fun user -> `O ["kind",str "User";"apiGroup",str K.Input.group;"name",str user]) users)]
let source xs = json (`O ["apiVersion",str "v1";"kind",str "List";"items",`A xs])
let scope resource = ["subject",str "workload";"namespace",str "apps";"resource",str resource;
  "names",strings [if resource="configmaps" then "app" else "db"]]
let requirements = `O ["schema_version",`Number "1";"kind",str K.Contract_spec.kind;
  "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
    "identities",`A (List.map (fun username -> `O ["username",str username;"groups",`A []]) ["deployer";"workload";"observer"])];
  "clauses",`A [`O (["name",str "available";"kind",str "must_allow"] @ scope "configmaps");
    `O (["name",str "private";"kind",str "must_not_grant"] @ scope "secrets")];
  "change_scope",`A [`O (scope "secrets")]]
let target ?(kind="Role") ?(ns=`String "apps") name =
  `O ["kind",str kind;"namespace",ns;"name",str name]
let step ?(kind="Role") ?(ns=`String "apps") operation name =
  `O ["operation",str operation;"target",target ~kind ~ns name]
let change ?(version=2) ?(requirements=requirements) operation target =
  `O ["schema_version",`Number (string_of_int version);"kind",str C.kind;"actor",str "deployer";
    "operation",str operation;"target",target;"requirements",requirements]
let sequence ?(version=2) ?(requirements=requirements) ?(invariants=["available"]) steps =
  `O (["schema_version",`Number (string_of_int version);"kind",str S.kind;"actor",str "deployer";
    "steps",`A steps;"requirements",requirements] @ if version=1 then [] else ["invariants",strings invariants])
let spec value = S.of_string (json value) |> ok
let config=rr ~names:["app"] ["configmaps"]
let secret=rr ~names:["db"] ["secrets"]
let authority ?(verbs=["create";"update";"delete"]) ?(names=[]) () =
  [role ~kind:"ClusterRole" ~ns:"" "authority"
    [rr ~group:K.Input.group ~verbs ~names ["roles";"rolebindings";"clusterroles";"clusterrolebindings"];config];
   binding ~kind:"ClusterRoleBinding" ~ns:"" ~role_kind:"ClusterRole" "authority" "authority" ["deployer"]]
let admin=authority ()
let keeper=[role "keep" [config];binding "keep" "keep" ["workload"]]
let old=[role "old" [config;secret];binding "old" "old" ["workload"]]
let replacement=[role "new" [config];binding "new" "new" ["workload"]]
let migration_steps=[step "create" "new";step ~kind:"RoleBinding" "create" "new";
  step ~kind:"RoleBinding" "delete-existing" "old";step "delete-existing" "old"]
let before=source (admin@old)
let after=source (admin@replacement)
let frozen=spec (sequence migration_steps)
let run ?z3 ?(spec=frozen) ?(before=before) after = P.run ?z3 spec ~before ~after
let outcome name expected t =
  check (name^"\n"^P.to_human t) ((P.evaluation t).outcome=expected);
  check (name^" coherent") (P.validate_evaluation t=Ok ())
let provenance : Evidence.provenance = {executable_sha256=String.make 64 'a';ocaml_version="test";z3_version=Ok "test"}
let evidence name t =
  let files=P.evidence_files provenance t |> ok in
  let manifest=List.assoc "manifest.json" files |> parse in
  let artifacts=match field "artifacts" manifest with `A xs -> xs | _ -> assert false in
  check (name^" artifacts complete") (List.length artifacts=List.length files-1);
  List.iter (fun x ->
    let path=match field "path" x with `String x -> x | _ -> assert false in
    let data=List.assoc path files in
    check (name^" hash "^path) (field "sha256" x=str (Sha256.string data));
    check (name^" bytes "^path) (field "bytes" x=`Number (string_of_int (String.length data)))) artifacts;
  files

(* A real-solver proxy changes exactly one frozen query. This independently
   exercises fail-closed invariant handling without making the final gate fail. *)
let () =
  if Array.length Sys.argv>=2 && Sys.argv.(1)="-version" then begin
    print_endline "Z3 version retirement-query-fixture";exit 0
  end;
  if Array.length Sys.argv>=3 && Sys.argv.(1)="-smt2" then begin
    let ch=open_in_bin Sys.argv.(2) in
    let query=really_input_string ch (in_channel_length ch) in close_in ch;
    let full=Sys.getenv_opt "SOUNDCHECK_RETIREMENT_QUERY"=Some (Sha256.string query) in
    if full || Sys.getenv_opt "SOUNDCHECK_RETIREMENT_CHECK"=Some (Sha256.string query) then begin
      if Sys.getenv_opt "SOUNDCHECK_RETIREMENT_REPLY"=Some "unknown" then print_endline "unknown"
      else begin
        print_endline "sat";
        if full then print_endline "((path \"\") (method \"get\") (is_anon false) (src_ip #x00000000) (host \"\") (scheme \"\") (sni \"\") (principal_name \"workload\") (has_object_request true) (object_namespace \"apps\") (object_kind \"configmaps\") (object_name \"app\"))"
      end;exit 0
    end else Unix.execvp "z3" [|"z3";"-smt2";Sys.argv.(2)|]
  end

let () =
  check "v2 roundtrip" (S.canonical (S.of_string (S.canonical frozen) |> ok)=S.canonical frozen);
  let selected=sequence ~invariants:["private";"available"] migration_steps in
  check "invariant selection is a canonical set"
    (S.canonical (spec selected)=S.canonical (spec (replace "invariants" (strings ["available";"private"]) selected)));
  List.iter (fun (name,value) -> check name (Result.is_error (S.of_string (json value)))) [
    "unknown invariant",sequence ~invariants:["typo"] migration_steps;
    "duplicate invariant",sequence ~invariants:["available";"available"] migration_steps;
    "object invariant rejected",replace "invariants" (`A [`O ["name",str "available"]]) (sequence migration_steps);
    "v1 cannot select invariants",add "invariants" (`A []) (sequence ~version:1 [step "update-existing" "old"]);
    "v1 cannot delete",sequence ~version:1 migration_steps;
    "missing selection",`O (List.remove_assoc "invariants" (fields (sequence migration_steps)));
    "future version",replace "schema_version" (`Number "3") (sequence migration_steps);
    "repeated target",sequence [step "delete-existing" "old";step "create" "old"];
    "step invariant override",sequence [add "invariants" (`A []) (step "delete-existing" "old")]];
  check "change v1 cannot delete" (Result.is_error (C.of_string (json (change ~version:1 "delete-existing" (target "old")))));
  check "change v2 roundtrip" (let c=C.of_string (json (change "delete-existing" (target "old"))) |> ok in
    C.canonical (C.of_string (C.canonical c) |> ok)=C.canonical c && C.version c=2);
  let valid=run after in
  outcome "mixed replacement without special authority passes" P.Valid_sequence valid;
  let view=P.evaluation valid in
  check "all five states checked" (List.map (fun (x : P.invariant) -> x.state) view.state_invariants=[0;1;2;3;4]);
  check "delete skips unnecessary coverage" (List.for_all (fun (x : P.step) ->
    match C.operation x.change,x.authorization with
    | C.Delete_existing,Some a -> a.allowed && a.special=None && a.coverage=None
      && a.initial.attributes.verb="delete" && a.initial.attributes.name="old"
    | _,Some a -> a.allowed | _ -> false) view.steps);
  List.iter (fun (x : P.invariant) -> match x.verification with
    | None -> check "executed invariant" false
    | Some v ->
      check "whole outer identity" (v.report.frozen_spec=Some (S.frozen_spec frozen));
      check "selected property" (v.report.property_name="rbac-sequence-invariants");
      check "only selected clauses planned" (List.for_all (fun (q : Contract_verify.obligation) -> q.clauses=["available"]) x.queries);
      check "trace protocol valid" (Evidence.verification_stages v.report v.trace=Ok ());
      let stopped=List.map (fun (t : Contract_verify.trace_entry) -> {t with execution=Contract_verify.Not_executed}) v.trace in
      check "truncated trace rejected" (Result.is_error (Evidence.verification_stages v.report stopped))) view.state_invariants;
  let files=evidence "valid" valid in
  check "v2 report and profile" (let report=P.to_json valid |> parse in
    field "schema_version" report=`Number "2" &&
    field "profile" (field "assurance" report)=str (P.profile_id_for_version 2));
  check "all snapshots retained" (List.for_all (fun i -> List.mem_assoc (Printf.sprintf "states/state-%03d.json" i) files) [0;1;2;3;4]);
  check "state bundle binds exact input" (let bundle=List.assoc "invariants/state-000/manifest.json" files |> parse in
    field "sha256" (field "config" bundle)=str (Sha256.string before));
  check "invariant bundle frozen identity" (List.assoc "invariants/state-000/contract.json" files=S.canonical frozen^"\n");
  let initial=run ~spec:(spec selected) after in
  outcome "initial violation cannot be called throughout" P.Invariant_failed initial;
  check "baseline state zero" ((P.evaluation initial).failing_step=Some 0 && P.exit_code initial=3);
  let initial_files=evidence "initial failure" initial in
  check "skipped invariant plans retained" (List.mem_assoc "invariants/state-001/plan.json" initial_files &&
    not (List.mem_assoc "invariants/state-001/manifest.json" initial_files));
  check "selection changes frozen identity" (S.canonical frozen<>S.canonical (spec selected));
  let wrong_order=spec (sequence [step "delete-existing" "old";step ~kind:"RoleBinding" "delete-existing" "old";
    step "create" "new";step ~kind:"RoleBinding" "create" "new"]) in
  let invalid=run ~spec:wrong_order after in
  outcome "role deletion cannot leave a dangling reference" P.Unknown invalid;
  check "unsupported before authorizing" ((P.evaluation invalid).phase=P.Preparation && (P.evaluation invalid).steps=[]);
  outcome "extra candidate mutation rejected" P.Unknown (run (source (admin@replacement@[role "extra" []])));
  outcome "retained deletion target rejected" P.Unknown (run (source (admin@replacement@old)));

  (* All four deletion kinds: the actor lacks both special authority and the
     deleted policy's Secret permission. Deletion is nevertheless authorized. *)
  List.iter (fun kind ->
    let cluster=kind="ClusterRole" || kind="ClusterRoleBinding" in
    let ns=if cluster then "" else "apps" in
    let t=target ~kind ~ns:(if cluster then `Null else str ns) "retired" in
    let extras,object_ = if kind="Role" || kind="ClusterRole" then [],role ~kind ~ns "retired" [secret]
      else let role_kind=if cluster then "ClusterRole" else "Role" in
        [role ~kind:role_kind ~ns "retired-role" [secret]],
        binding ~kind ~ns ~role_kind "retired" "retired-role" ["workload"] in
    let scoped_requirements = if kind<>"ClusterRoleBinding" then requirements else
      let clauses=match field "clauses" requirements with `A xs -> List.map (add "verb" (str "get")) xs | _ -> assert false in
      requirements |> replace "schema_version" (`Number "4") |> replace "clauses" (`A clauses)
        |> replace "change_scope" (`A [`O (("verb",str "get") ::
          List.map (fun (key,value) -> key,if key="namespace" then `O ["exclude",`A []] else value) (scope "secrets"))]) in
    let c=C.of_string (json (change ~requirements:scoped_requirements "delete-existing" t)) |> ok in
    let b=source (admin@keeper@extras@[object_]) and a=source (admin@keeper@extras) in
    if kind="ClusterRoleBinding" then begin
      let narrow=C.of_string (json (change "delete-existing" t)) |> ok in
      check "cluster binding deletion needs a cluster-wide approved scope"
        ((K.Policy_change.evaluation (K.Policy_change.run narrow ~before:b ~after:a)).outcome=K.Policy_change.Out_of_scope_regression)
    end;
    let result=K.Policy_change.run c ~before:b ~after:a in
    check (kind^" deletion") ((K.Policy_change.evaluation result).outcome=K.Policy_change.Valid_change);
    let authorization=K.Policy_change.authorize c ~before:b ~after:a |> ok in
    check (kind^" named request only") (authorization.allowed && authorization.special=None && authorization.coverage=None &&
      authorization.initial.attributes.namespace=ns && authorization.initial.attributes.name="retired");
    let denied_before=source (authority ~verbs:["update"] ()@keeper@extras@[object_]) in
    let denied_after=source (authority ~verbs:["update"] ()@keeper@extras) in
    check (kind^" update does not authorize delete")
      ((K.Policy_change.evaluation (K.Policy_change.run c ~before:denied_before ~after:denied_after)).outcome=K.Policy_change.Authorization_failed);
    check (kind^" missing target") (Result.is_error (K.Policy_change.authorize c ~before:a ~after:a));
    check (kind^" target remains") (Result.is_error (K.Policy_change.authorize c ~before:b ~after:b));
    let named=authority ~verbs:["delete"] ~names:["retired"] () in
    check (kind^" named delete accepted") ((K.Policy_change.authorize c
      ~before:(source (named@keeper@extras@[object_])) ~after:(source (named@keeper@extras)) |> ok).allowed);
    let named=authority ~verbs:["delete"] ~names:["other"] () in
    check (kind^" wrong name denied") (not ((K.Policy_change.authorize c
      ~before:(source (named@keeper@extras@[object_])) ~after:(source (named@keeper@extras)) |> ok).allowed));
    let single=spec (sequence ~requirements:scoped_requirements [step ~kind ~ns:(if cluster then `Null else str ns) "delete-existing" "retired"]) in
    outcome (kind^" one-step equivalence") P.Valid_sequence (run ~spec:single ~before:b a))
    ["Role";"ClusterRole";"RoleBinding";"ClusterRoleBinding"];

  let handoff_requirements=replace "change_scope" (`A [`O (scope "configmaps");`O (scope "secrets")]) requirements in
  let handoff_before=source (admin@[role "a" [config];role "b" [];binding "a" "a" ["workload"];binding "b" "b" ["workload"]]) in
  let handoff_after=source (admin@[role "a" [];role "b" [config];binding "a" "a" ["workload"];binding "b" "b" ["workload"]]) in
  let handoff_steps=[step "update-existing" "a";step "update-existing" "b"] in
  let handoff_spec=spec (sequence ~requirements:handoff_requirements handoff_steps) in
  let loss=run ~spec:handoff_spec ~before:handoff_before handoff_after in
  outcome "in-scope temporary loss fails selected invariant" P.Invariant_failed loss;
  check "first post-step state" ((P.evaluation loss).failing_step=Some 1);
  outcome "replacement-first preserves availability" P.Valid_sequence
    (run ~spec:(spec (sequence ~requirements:handoff_requirements (List.rev handoff_steps))) ~before:handoff_before handoff_after);
  outcome "empty selection permits final-only repair" P.Valid_sequence
    (run ~spec:(spec (sequence ~requirements:handoff_requirements ~invariants:[] handoff_steps)) ~before:handoff_before handoff_after);
  let legacy=run ~spec:(spec (sequence ~version:1 ~requirements:handoff_requirements handoff_steps)) ~before:handoff_before handoff_after in
  outcome "v1 remains final-only" P.Valid_sequence legacy;
  check "v1 report stays schema1 without invariant fields" (let j=P.to_json legacy |> parse in
    field "schema_version" j=`Number "1" && not (List.mem_assoc "state_invariants" (fields j)));

  let special=authority ~verbs:["create";"update";"delete";"bind";"escalate"] () in
  let exposure_before=source (special@keeper@[role "temporary" [];binding "cut" "temporary" ["workload"]]) in
  let exposure_after=source (special@keeper@[role "temporary" [secret];binding "cut" "temporary" []]) in
  let exposure_steps=[step "update-existing" "temporary";step ~kind:"RoleBinding" "update-existing" "cut"] in
  let exposure=run ~spec:(spec (sequence ~invariants:["private"] exposure_steps))
    ~before:exposure_before exposure_after in
  outcome "temporary in-scope forbidden grant violates invariant" P.Invariant_failed exposure;
  check "temporary exposure at state1" ((P.evaluation exposure).failing_step=Some 1);
  outcome "remove subject before expansion avoids exposure" P.Valid_sequence
    (run ~spec:(spec (sequence ~invariants:["private"] (List.rev exposure_steps))) ~before:exposure_before exposure_after);

  let revoke_steps=[step ~kind:"ClusterRoleBinding" ~ns:`Null "delete-existing" "authority";
    step ~kind:"ClusterRole" ~ns:`Null "delete-existing" "authority"] in
  let revoke=run ~spec:(spec (sequence revoke_steps)) ~before:(source (admin@keeper)) (source keeper) in
  outcome "prior removal revokes later authority" P.Authorization_failed revoke;
  check "revoked at second step" ((P.evaluation revoke).failing_step=Some 2);
  let raw=role "retired" [] in
  List.iter (fun (key,value) ->
    let object_=replace "metadata" (add key value (field "metadata" raw)) raw in
    let c=C.of_string (json (change "delete-existing" (target "retired"))) |> ok in
    check (key^" rejected") (Result.is_error (K.Policy_change.authorize c
      ~before:(source (admin@keeper@[object_])) ~after:(source (admin@keeper)))))
    ["finalizers",strings ["example.test/hold"];"ownerReferences",`A [];"deletionTimestamp",str "2026-11-15T00:00:00Z"];

  let first=List.hd view.state_invariants in
  let query=List.find (fun (q : Contract_verify.obligation) -> q.phase=Contract_verify.Clause) first.queries in
  let final_trace=Option.get (Option.get view.comparison).trace in
  check "proxy query is specific to an invariant state"
    (not (List.exists (fun (t : Contract_verify.trace_entry) -> t.obligation.smtlib=query.smtlib) final_trace.candidate));
  Unix.putenv "SOUNDCHECK_RETIREMENT_QUERY" (Sha256.string query.smtlib);
  Unix.putenv "SOUNDCHECK_RETIREMENT_CHECK" (Sha256.string (Solver_protocol.query query.smtlib).check);
  let executable=Filename.concat (Sys.getcwd ()) Sys.argv.(0) in
  let executable=if Filename.is_relative Sys.argv.(0) then executable else Sys.argv.(0) in
  Unix.putenv "SOUNDCHECK_RETIREMENT_REPLY" "unknown";
  let unknown=run ~z3:executable after in
  outcome "invariant solver unknown fails closed" P.Unknown unknown;
  check "unknown in invariant phase" ((P.evaluation unknown).phase=P.State_invariants && P.exit_code unknown=4);
  Unix.putenv "SOUNDCHECK_RETIREMENT_REPLY" "invalid-model";
  let invalid=run ~z3:executable after in
  outcome "invariant SAT witness must actually violate selected clause" P.Unknown invalid;
  check "invalid witness stays invariant unknown" ((P.evaluation invalid).phase=P.State_invariants);
  check "invalid witness rejected by semantic validator" (match
    (List.hd (P.evaluation invalid).state_invariants).verification with
    | Some {report={result=Report.Unknown reason;_};_} ->
      String.starts_with ~prefix:"solver witness validation failed" reason
    | _ -> false);
  ignore (evidence "invalid witness" invalid);
  Unix.putenv "SOUNDCHECK_RETIREMENT_QUERY" "";
  Unix.putenv "SOUNDCHECK_RETIREMENT_CHECK" "";
  Printf.printf "policy retirement: %d checks passed\n" !count
