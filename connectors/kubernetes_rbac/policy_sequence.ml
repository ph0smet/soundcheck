open Soundcheck_core
module I = Input
let ( let* ) = Result.bind

type outcome = Valid_sequence | Authorization_failed | Contract_failed | Invariant_failed | Out_of_scope_regression | Unknown
type phase = Preparation | Authorization | Final_verification | State_invariants | Intermediate_preservation | Complete
let phase_name = function Preparation -> "preparation" | Authorization -> "authorization"
  | Final_verification -> "final_verification" | State_invariants -> "state_invariants"
  | Intermediate_preservation -> "intermediate_preservation"
  | Complete -> "complete"
type step = { index : int; change : Change_spec.t; before_sha256 : string; after_sha256 : string;
  authorization : Policy_change.authorization option }
type invariant = { state : int; state_sha256 : string; queries : Contract_verify.obligation list;
  verification : Verify.selected option }
type intermediate = { step : int; query : string; verification : Verify.preservation option }
type t = { outcome : outcome; phase : phase; failing_step : int option; reason : string;
  spec : Sequence_spec.t option; before : string; after : string; z3 : string option;
  states : string list; steps : step list; intermediate_preservation : intermediate list;
  state_invariants : invariant list;
  comparison : Verify.comparison option }
type evaluation = { outcome : outcome; frozen_contract : string option;
  before_sha256 : string; after_sha256 : string; authorization_allowed : bool option;
  comparison : Verify.comparison option; phase : phase; failing_step : int option;
  steps : step list; intermediate_preservation : intermediate list; state_invariants : invariant list }

let profile_id = "kubernetes-rbac-v1.34-policy-sequence-v1"
let str x = `String x
let number n = `Number (string_of_int n)
let optional f = function None -> `Null | Some x -> f x
let digest source = `O ["sha256",str (Sha256.string source);"bytes",number (String.length source)]
let profile_human = "Ordered RBAC policy sequences ["^profile_id^"] (Kubernetes v1.34.0)\n\
  1..16 distinct create/update-existing targets and one frozen actor.\n\
  Authorize each step from its immediately preceding complete inventory.\n\
  Preserve original modeled decisions outside the frozen scope at EVERY post-step state.\n\
  Require frozen access clauses only at the final state; intermediate in-scope deviations are permitted.\n\
  Conditional on successful visible prior writes, without concurrent changes or controller reconciliation.\n\
  No atomic deployment, admission, runtime effects or composed-authorizer guarantee.\n"
let profile_json = I.json (`O ["schema_version",number 1;"id",str profile_id;
  "kubernetes_version",str "1.34.0";"max_steps",number Sequence_spec.max_steps;
  "authorization_method",str "deterministic-native-rbac-policy-coverage";
  "scope",str "One actor; ordered distinct create/update-existing Role, ClusterRole, RoleBinding or ClusterRoleBinding targets.";
  "assumptions",`A (List.map str [
    "Complete static inventories and independently trusted fixed actor/groups; each prior write succeeds and becomes visible before the next operation.";
    "Every derived state preserves original modeled decisions outside the frozen change scope. Access clauses apply only at the final state; intermediate in-scope deviations are permitted.";
    "Targets are written once; intermediate objects come only from the final candidate in frozen order. Untargeted objects remain unchanged after map-key normalization.";
    "No repeated targets, system:masters actor, aggregate target, roleRef mutation, no-op/metadata-only update, patch/apply/delete, impersonation or create-on-update.";
    "No concurrent changes, controller reconciliation, atomic deployment, admission, storage, successful mutation, runtime effects or composed authorization-chain guarantee.";
    "Full native policy coverage keeps unknown resource/verb/group strings. Access and preservation retain the nested requirements schema's domain and frozen identities.";
    "Per step: at most 100000 input values, 8 MiB input strings, 100000 proposed atoms, 8 MiB expanded atom strings, 10000000 comparison units. At most 16 steps; exceeded limits return unknown, never truncation."])])

let profile_id_for_version = function
  | 1 -> profile_id | 2 -> "kubernetes-rbac-v1.34-policy-sequence-v2"
  | _ -> invalid_arg "unsupported policy-sequence version"
let profile_human_for_version = function
  | 1 -> profile_human
  | 2 -> "Ordered RBAC retirement and migration ["^profile_id_for_version 2^"] (Kubernetes v1.34.0)\n\
    One actor; 1..16 distinct create/update-existing/delete-existing targets.\n\
    Each operation uses its immediately preceding complete inventory; ordinary delete requires only its named delete grant.\n\
    Preserve baseline decisions outside the frozen scope after every step; require all access clauses at the final state.\n\
    Selected invariant clauses must also hold at S0 and every post-step state, including inside the change scope.\n\
    Conditional on successful visible writes and fully completed deletion with default options; no concurrent writes or controller reconciliation.\n\
    No repeated targets, aggregate targets, unsafe deletion, atomic deployment, admission, runtime effects or composed-authorizer guarantee.\n"
  | _ -> invalid_arg "unsupported policy-sequence version"
let profile_json_for_version = function
  | 1 -> profile_json
  | 2 -> I.json (`O ["schema_version",number 2;"id",str (profile_id_for_version 2);
    "kubernetes_version",str "1.34.0";"max_steps",number Sequence_spec.max_steps;
    "authorization_method",str "deterministic-native-rbac-policy-coverage";
    "scope",str "One actor; ordered distinct create/update-existing/delete-existing Role, ClusterRole, RoleBinding or ClusterRoleBinding targets.";
    "assumptions",`A (List.map str [
      "Complete strict inventories and independently trusted fixed actor/groups; each prior operation succeeds and becomes fully visible before the next.";
      "Ordinary named delete-existing requires only its initial delete grant and removes exactly its existing target. Default DELETE options only; no bind/escalate/coverage prerequisite for deletion.";
      "Preserve original modeled decisions outside the approved scope at EVERY post-step state; all access clauses hold at the final state.";
      "The selected existing invariant clauses also hold at S0 and EVERY post-step state, using the same frozen identities and request domain. Unselected final requirements may be violated inside scope at intermediate states.";
      "Distinct targets permit deterministic states from original/final inventories; replacement policies use new names. Strict references and aggregate consistency must hold in every state.";
      "No repeated targets, system:masters actor, aggregate target, roleRef mutation, no-op/metadata-only update, patch/apply, bulk deletion, unsafe deletion options, impersonation or create-on-update.";
      "No finalizers, owner references or deletion timestamps. No concurrent changes, controller reconciliation, atomic deployment, storage, garbage collection, admission, runtime effects or composed authorization-chain guarantee.";
      "Existing per-operation native-policy coverage bounds apply. Maximum 16 steps; overflow yields unknown without truncation."])])
  | _ -> invalid_arg "unsupported policy-sequence version"

let object_key (v : Snapshot.object_view) = v.object_kind,v.object_namespace,v.object_name
let target_key change = let t = Change_spec.target change in t.kind,t.namespace,t.name
let prepare spec ~before ~after =
  let error ?step reason = Error (step,reason) in
  let* originals = Snapshot.object_views before |> Result.map_error (fun e -> None,"baseline: "^e) in
  let* proposed = Snapshot.object_views after |> Result.map_error (fun e -> None,"candidate: "^e) in
  let keys = List.map target_key (Sequence_spec.steps spec) in
  let others objects = objects |> List.filter (fun obj -> not (List.mem (object_key obj) keys))
    |> List.map (fun obj -> object_key obj,obj.Snapshot.canonical_object) |> List.sort Stdlib.compare in
  let* () = if others originals=others proposed then Ok ()
    else error "only frozen sequence targets may change; unrelated object contents must agree after map-key normalization" in
  let count = List.length keys in
  let rec derive index current states = function
    | [] -> Ok (List.rev states)
    | change::rest ->
      let key = target_key change in
      let original = List.find_opt (fun obj -> object_key obj=key) current in
      let* target = match Change_spec.operation change,original,List.find_opt (fun obj -> object_key obj=key) proposed with
        | Delete_existing,Some old,None -> Ok old
        | Delete_existing,None,_ -> error ~step:index "delete-existing requires an existing target before its step"
        | Delete_existing,_,Some _ -> error ~step:index "delete-existing requires target absence from the final candidate"
        | _,_,Some obj -> Ok obj | _,_,None -> error ~step:index "candidate must contain every frozen target" in
      let* () = match Change_spec.operation change,original with
        | Create,None | Update_existing,Some _ | Delete_existing,Some _ -> Ok ()
        | Create,Some _ -> error ~step:index "create requires the frozen target to be absent before its step"
        | Update_existing,None -> error ~step:index "update-existing requires an original target; create-on-update is unsupported"
        | Delete_existing,None -> error ~step:index "delete-existing requires an original target" in
      let* () = if target.aggregated || Option.fold ~none:false ~some:(fun old -> old.Snapshot.aggregated) original
        then error ~step:index "aggregate ClusterRole targets are outside the policy-sequence profile" else Ok () in
      let* () = match Change_spec.operation change,original with
        | Delete_existing,_ | _,None -> Ok ()
        | _,Some old -> (match old.object_spec,target.object_spec with
          | Binding_spec a,Binding_spec b when a.role_ref<>b.role_ref -> error ~step:index "binding roleRef is immutable"
          | _ when old.object_spec=target.object_spec -> error ~step:index "update-existing requires a typed rule or subject change; no-op and metadata-only updates are unsupported"
          | _ -> Ok ()) in
      let next = match Change_spec.operation change,original with
        | Delete_existing,_ -> List.filter (fun obj -> object_key obj<>key) current
        | _,None -> current @ [target]
        | _,Some _ -> List.map (fun obj -> if object_key obj=key then target else obj) current in
      let source = if index=count then after else I.json (`O ["apiVersion",str "v1";"kind",str "List";
        "items",`A (List.map (fun obj -> I.parse obj.Snapshot.canonical_object) next)]) in
      let* () = match Snapshot.of_string source with
        | Ok _ -> Ok () | Error reason -> error ~step:index ("unsupported post-step inventory: "^reason) in
      derive (index+1) next (source::states) rest in
  derive 1 originals [before] (Sequence_spec.steps spec)

let result_name = function Valid_sequence -> "valid_sequence" | Authorization_failed -> "authorization_failed"
  | Contract_failed -> "contract_failed" | Invariant_failed -> "invariant_failed"
  | Out_of_scope_regression -> "out_of_scope_regression" | Unknown -> "unknown"
let authorization_allowed steps =
  if List.exists (fun step -> Option.fold ~none:false ~some:(fun a -> not a.Policy_change.allowed) step.authorization) steps
  then Some false
  else if steps<>[] && List.for_all (fun step -> step.authorization<>None) steps then Some true else None
let evaluation (t : t) : evaluation = { outcome=t.outcome;
  frozen_contract=Option.map Sequence_spec.canonical t.spec;before_sha256=Sha256.string t.before;
  after_sha256=Sha256.string t.after;authorization_allowed=authorization_allowed t.steps;
  comparison=t.comparison;phase=t.phase;failing_step=t.failing_step;steps=t.steps;
  intermediate_preservation=t.intermediate_preservation;state_invariants=t.state_invariants }
let invalid_contract reason ~before ~after = {outcome=Unknown;phase=Preparation;failing_step=None;reason;
  spec=None;before;after;z3=None;states=[];steps=[];intermediate_preservation=[];state_invariants=[];comparison=None}

let run ?z3 spec ~before ~after =
  let initial = { (invalid_contract "" ~before ~after) with spec=Some spec;z3 } in
  match prepare spec ~before ~after with
  | Error (failing_step,reason) -> {initial with failing_step;reason}
  | Ok states ->
    let states_array = Array.of_list states in
    let steps = List.mapi (fun i change -> {index=i+1;change;
      before_sha256=Sha256.string states_array.(i);after_sha256=Sha256.string states_array.(i+1);
      authorization=None}) (Sequence_spec.steps spec) in
    let requirements = Sequence_spec.requirements spec in
    let plans = List.init (List.length steps-1) (fun i ->
      Verify.plan_preservation requirements ~before ~after:states_array.(i+1)) in
    (* Every state is already validated; still propagate preparation failure. *)
    let rec collect i acc = function
      | [] -> Ok (List.rev acc)
      | Error reason::_ -> Error (Some i,reason)
      | Ok plan::rest -> collect (i+1) (plan::acc) rest in
    match collect 1 [] plans with
    | Error (failing_step,reason) -> {initial with failing_step;reason}
    | Ok plans ->
      let intermediate_preservation = List.mapi (fun i plan ->
        {step=i+1;query=Verify.preservation_query plan;verification=None}) plans in
      let invariant_plans = if Sequence_spec.invariants spec=[] then Ok [] else
        List.map (Verify.plan_selected requirements ~clauses:(Sequence_spec.invariants spec)
          ~frozen_spec:(Sequence_spec.frozen_spec spec)) states |> collect 0 [] in
      match invariant_plans with
      | Error (failing_step,reason) -> {initial with failing_step;reason}
      | Ok invariant_plans ->
      let state_invariants = List.mapi (fun state plan ->
        {state;state_sha256=Sha256.string states_array.(state);
          queries=Verify.selected_queries plan;verification=None}) invariant_plans in
      let planned = {initial with states;steps;intermediate_preservation;state_invariants} in
      let rec authorize done_ = function
        | [] -> Ok (List.rev done_)
        | step::rest ->
          let prior=states_array.(step.index-1) and next=states_array.(step.index) in
          match Policy_change.authorize step.change ~before:prior ~after:next with
          | Error reason -> Error {planned with phase=Authorization;failing_step=Some step.index;reason;
              steps=List.rev_append done_ (step::rest)}
          | Ok a ->
            let step = {step with authorization=Some a} in
            if not a.allowed then Error {planned with outcome=Authorization_failed;phase=Authorization;
              failing_step=Some step.index;reason=a.reason;steps=List.rev_append done_ (step::rest)}
            else authorize (step::done_) rest in
      match authorize [] steps with
      | Error report -> report
      | Ok steps ->
        let comparison = Verify.compare_with_trace ?z3 requirements ~before ~after in
        let checked = {planned with steps;comparison=Some comparison;phase=Final_verification;
          failing_step=Some (List.length steps)} in
        match comparison.report.result with
        | Report.Unknown reason -> {checked with reason}
        | (Vacuous | Inconsistent _ | Violated _) ->
          (match comparison.candidate_report with
          | Some {result=Proved;_} -> {checked with outcome=Out_of_scope_regression;
              reason="Final candidate changes a modeled permission outside the frozen approved scope."}
          | _ -> {checked with outcome=Contract_failed;reason="Final candidate does not satisfy the frozen access requirements."})
        | Proved ->
          let rec check_invariants done_ obligations plans = match obligations,plans with
            | [],[] -> Ok {checked with state_invariants=List.rev done_}
            | (obligation : invariant)::rest,plan::other ->
              let verification = Verify.execute_selected ?z3 plan in
              let obligation = {obligation with verification=Some verification} in
              (match verification.report.result with
               | Proved -> check_invariants (obligation::done_) rest other
               | result -> Error {checked with phase=State_invariants;failing_step=Some obligation.state;
                   outcome=(match result with Report.Unknown _ -> Unknown | _ -> Invariant_failed);
                   reason=(match result with Report.Unknown reason -> reason
                     | _ -> "Selected frozen invariant clauses do not hold at this sequence state.");
                   state_invariants=List.rev_append done_ (obligation::rest)})
            | _ -> assert false in
          match check_invariants [] state_invariants invariant_plans with
          | Error failure -> failure
          | Ok checked ->
          let rec preserve done_ obligations plans = match obligations,plans with
            | [],[] -> {checked with outcome=Valid_sequence;phase=Complete;failing_step=None;
                intermediate_preservation=List.rev done_;
                reason=(if Sequence_spec.version spec=1 then
                    "Every ordered operation is authorized; final access and preservation at every post-step state passed. Intermediate deviations inside the approved scope are permitted."
                  else "Every ordered operation is authorized; final access, selected invariants at S0 and every post-step state, and preservation outside scope at every post-step state passed. Unselected final-only requirements may deviate inside scope at intermediate states.")}
            | (obligation : intermediate)::rest,plan::other ->
              let verification = Verify.execute_preservation ?z3 plan in
              let obligation = {obligation with verification=Some verification} in
              (match verification.report.result with
              | Proved -> preserve (obligation::done_) rest other
              | result -> {checked with phase=Intermediate_preservation;failing_step=Some obligation.step;
                  outcome=(match result with Report.Violated _ -> Out_of_scope_regression | _ -> Unknown);
                  reason=(match result with Report.Unknown reason -> reason
                    | _ -> "An intermediate state changes a modeled permission outside the frozen approved scope.");
                  intermediate_preservation=List.rev_append done_ (obligation::rest)})
            | _ -> assert false in
          preserve [] intermediate_preservation plans

let validate_evaluation (t : t) =
  let ensure yes reason = if yes then Ok () else Error reason in
  let* () = match t.spec with
    | None -> ensure (t.outcome=Unknown && t.phase=Preparation && t.states=[] && t.steps=[] &&
        t.comparison=None && t.intermediate_preservation=[] && t.state_invariants=[]) "invalid-contract run carries executed stages"
    | Some _ -> Ok () in
  if t.phase=Preparation then
    ensure (t.outcome=Unknown && t.states=[] && t.steps=[] && t.comparison=None && t.intermediate_preservation=[] && t.state_invariants=[])
      "preparation failure carries later stages"
  else
    let* spec = match t.spec with Some spec -> Ok spec | None -> Error "missing frozen sequence" in
    let changes=Sequence_spec.steps spec in
    let count=List.length changes in
    let* () = ensure (List.length t.states=count+1 && List.length t.steps=count &&
      List.length t.intermediate_preservation=count-1) "incomplete state/step/preservation plan" in
    let states=Array.of_list t.states in
    let* () = ensure (states.(0)=t.before && states.(count)=t.after) "state endpoints differ from exact inputs" in
    let* () = ensure (List.for_all2 (fun (step : step) change ->
      step.index>=1 && step.index<=count && Change_spec.canonical step.change=Change_spec.canonical change &&
      step.before_sha256=Sha256.string states.(step.index-1) && step.after_sha256=Sha256.string states.(step.index))
      t.steps changes && List.map (fun step -> step.index) t.steps=List.init count ((+) 1))
      "step identity or input chain mismatch" in
    let* () = ensure (List.map (fun p -> p.step) t.intermediate_preservation=List.init (count-1) ((+) 1))
      "intermediate preservation order mismatch" in
    let requirements=Sequence_spec.requirements spec in
    let frozen=Contract_spec.frozen_spec requirements in
    let prefix_assurance (r : Report.t) = r.assurance=Some (Assurance.assessment
      ~version:(Contract_spec.version requirements) ()) in
    let* () = ensure (List.for_all (fun (p : intermediate) -> match p.verification with
      | None -> true
      | Some v -> v.trace.smtlib=p.query && v.trace.id="preservation-outside-change-scope" &&
        v.report.frozen_spec=Some frozen && prefix_assurance v.report &&
        v.report.property_name="rbac-sequence-preservation" &&
        (match v.trace.execution,v.report.result with
        | Contract_verify.Executed Solve.Proved,Report.Proved -> v.report.clause=None
        | Executed (Solve.Unknown a),Report.Unknown b -> a=b && v.report.clause=None
        | Executed (Solve.Violated model),Report.Violated c ->
          c.principal=Option.value ~default:"" model.principal_name && c.action=model.method_ &&
          c.object_request=model.object_request && (model.object_request<>None || c.path=model.path) &&
          (match v.report.clause with Some {kind=Must_preserve;name;_} -> name=v.trace.id | _ -> false)
        | _ -> false)) t.intermediate_preservation) "incoherent intermediate report/execution" in
    let expected_states = if Sequence_spec.invariants spec=[] then [] else List.init (count+1) Fun.id in
    let* () = ensure (List.map (fun (p : invariant) -> p.state) t.state_invariants=expected_states)
      "incomplete invariant state plan" in
    let rec check_invariants = function
      | [] -> Ok ()
      | (p : invariant)::rest ->
        let* () = ensure (p.state_sha256=Sha256.string states.(p.state)) "invariant state digest mismatch" in
        let* plan = Verify.plan_selected requirements ~clauses:(Sequence_spec.invariants spec)
          ~frozen_spec:(Sequence_spec.frozen_spec spec) states.(p.state) in
        let* () = ensure (p.queries=Verify.selected_queries plan) "invariant plan does not match frozen clauses/state" in
        let* () = match p.verification with
          | None -> Ok ()
          | Some v ->
            let* () = ensure (v.report.frozen_spec=Some (Sequence_spec.frozen_spec spec) &&
              prefix_assurance v.report && v.report.property_name="rbac-sequence-invariants" &&
              List.map (fun (e : Contract_verify.trace_entry) -> e.obligation) v.trace=p.queries)
              "invariant report/trace identity mismatch" in
            let* () = Evidence.verification_stages v.report v.trace in
            let* () = ensure (match v.report.result,v.report.clause with
              | (Report.Proved|Report.Unknown _),None -> true
              | (Report.Violated _|Report.Vacuous|Report.Inconsistent _),Some clause ->
                List.mem clause.name (Sequence_spec.invariants spec) &&
                List.exists (fun (c : Contract_spec.clause) -> c.name=clause.name &&
                  clause.kind=(match c.kind with Must_allow -> Report.Must_allow | Must_not_grant -> Report.Must_not_grant))
                  (Contract_spec.clauses requirements)
              | _ -> false) "invariant report names an unselected or wrong-kind clause" in
            Ok () in
        check_invariants rest in
    let* () = check_invariants t.state_invariants in
    let* () = match t.comparison with
      | None -> Ok ()
      | Some c ->
        let* () = ensure (c.report.frozen_spec=Some frozen) "wrong final comparison identity" in
        (match c.candidate_report,c.trace with
        | Some candidate,Some trace ->
          let* () = ensure (candidate.frozen_spec=Some frozen) "wrong final candidate identity" in
          Evidence.comparison_stages c.report candidate trace
        | None,None -> ensure (match c.report.result with Report.Unknown _ -> true | _ -> false)
            "missing final comparison plan"
        | _ -> Error "incomplete final comparison stage") in
    let all_authorized=authorization_allowed t.steps=Some true in
    let all_unexecuted=List.for_all (fun (p : intermediate) -> p.verification=None) t.intermediate_preservation in
    let invariants_unexecuted=List.for_all (fun (p : invariant) -> p.verification=None) t.state_invariants in
    let invariants_proved=List.for_all (fun (p : invariant) -> Option.fold ~none:false
      ~some:(fun (v : Verify.selected) -> v.report.result=Report.Proved) p.verification) t.state_invariants in
    let final_proved=Option.fold ~none:false ~some:(fun (c : Verify.comparison) -> c.report.result=Report.Proved) t.comparison in
    let all_preserved=List.for_all (fun (p : intermediate) -> Option.fold ~none:false
      ~some:(fun v -> v.Verify.report.result=Report.Proved) p.verification) t.intermediate_preservation in
    let authorized_prefix failure = List.for_all (fun step ->
      if step.index<failure then Option.fold ~none:false ~some:(fun a -> a.Policy_change.allowed) step.authorization
      else if step.index>failure then step.authorization=None
      else match t.outcome,step.authorization with
        | Authorization_failed,Some a -> not a.allowed | Unknown,None -> true | _ -> false) t.steps in
    let at_failure f = match t.failing_step with Some i when i>=1 && i<=count -> f i | _ -> false in
    match t.phase with
    | Preparation -> assert false
    | Authorization -> ensure (t.comparison=None && all_unexecuted && invariants_unexecuted && at_failure authorized_prefix)
        "incoherent authorization failure"
    | Final_verification ->
      let* () = ensure (all_authorized && all_unexecuted && invariants_unexecuted && t.failing_step=Some count) "incoherent final phase prerequisites" in
      ensure (match t.outcome,t.comparison with
        | Unknown,Some {report={result=Report.Unknown _;_};_} -> true
        | Out_of_scope_regression,Some {report={result=Report.Violated _;_};candidate_report=Some {result=Report.Proved;_};_} -> true
        | Contract_failed,Some {candidate_report=Some {result=(Report.Violated _|Vacuous|Inconsistent _);_};_} -> true
        | _ -> false) "final outcome disagrees with comparison"
    | State_invariants ->
      ensure (all_authorized && final_proved && all_unexecuted &&
        match t.failing_step with
        | Some failure when failure>=0 && failure<=count && t.state_invariants<>[] ->
          List.for_all (fun (p : invariant) ->
            if p.state<failure then Option.fold ~none:false
              ~some:(fun (v : Verify.selected) -> v.report.result=Report.Proved) p.verification
            else if p.state>failure then p.verification=None
            else match t.outcome,p.verification with
              | Invariant_failed,Some {report={result=(Report.Violated _|Vacuous|Inconsistent _);_};_} -> true
              | Unknown,Some {report={result=Report.Unknown _;_};_} -> true
              | _ -> false) t.state_invariants
        | _ -> false) "incoherent invariant failure"
    | Intermediate_preservation ->
      ensure (all_authorized && final_proved && invariants_proved && at_failure (fun failure -> failure<count &&
        List.for_all (fun (p : intermediate) -> if p.step<failure then Option.fold ~none:false
          ~some:(fun v -> v.Verify.report.result=Report.Proved) p.verification
          else if p.step>failure then p.verification=None
          else match t.outcome,p.verification with
            | Out_of_scope_regression,Some {report={result=Report.Violated _;_};_} -> true
            | Unknown,Some {report={result=Report.Unknown _;_};_} -> true
            | _ -> false) t.intermediate_preservation)) "incoherent intermediate failure"
    | Complete -> ensure (t.outcome=Valid_sequence && t.failing_step=None && all_authorized && final_proved && all_preserved && invariants_proved)
        "success lacks required executed stages"

let target_json change = let target=Change_spec.target change in `O ["kind",str target.kind;
  "namespace",(if target.namespace="" then `Null else str target.namespace);"name",str target.name]
let status (value : Verify.preservation option) = match value with None -> "not_executed" | Some p -> (match p.Verify.report.result with
  | Report.Proved -> "proved" | Violated _ -> "violated" | _ -> "unknown")
let invariant_status (value : Verify.selected option) = match value with
  | None -> "not_executed"
  | Some v -> (match v.report.result with
    | Report.Proved -> "proved" | Violated _ -> "violated" | Vacuous -> "vacuous"
    | Inconsistent _ -> "inconsistent" | Unknown _ -> "unknown")
let version (t : t) = Option.fold ~none:1 ~some:Sequence_spec.version t.spec
let to_json (t : t) =
  let states=Array.of_list t.states in
  I.json (`O (["schema_version",number (version t);"kind",str Sequence_spec.kind;
    "result",str (result_name t.outcome);"reason",str t.reason;"phase",str (phase_name t.phase);
    "failing_step",optional number t.failing_step;
    "assurance",`O ["profile",str (profile_id_for_version (version t));"status",str (if t.outcome=Unknown then "unsupported_or_inconclusive" else "within_profile")];
    "frozen_spec",optional (fun spec -> `O ["schema_version",number (Sequence_spec.version spec);"kind",str Sequence_spec.kind;
      "canonical",str (Sequence_spec.canonical spec)]) t.spec;
    "inputs",`O ["before",digest t.before;"after",digest t.after];
    "states",`A (List.mapi (fun index source -> `O ["index",number index;"digest",digest source]) t.states);
    "steps",`A (List.map (fun step -> `O ["index",number step.index;
      "operation",str (Change_spec.operation_name (Change_spec.operation step.change));"target",target_json step.change;
      "inputs",`O ["before",digest states.(step.index-1);"after",digest states.(step.index)];
      "authorization",optional (fun a -> I.parse (Policy_change.authorization_json a)) step.authorization]) t.steps);
    "verification",optional (fun (c : Verify.comparison) -> `O ["comparison_report",I.parse (Report.to_json c.report);
      "candidate_report",optional (fun r -> I.parse (Report.to_json r)) c.candidate_report]) t.comparison;
    "intermediate_preservation",`A (List.map (fun (p : intermediate) -> `O ["step",number p.step;
      "inputs",`O ["before",digest t.before;"after",digest states.(p.step)];"status",str (status p.verification);
      "report",optional (fun (v : Verify.preservation) -> I.parse (Report.to_json v.report)) p.verification]) t.intermediate_preservation)]
    @ if version t=1 then [] else ["state_invariants",`A (List.map (fun (p : invariant) ->
      `O ["state",number p.state;"input",digest states.(p.state);
        "status",str (invariant_status p.verification);
        "report",optional (fun (v : Verify.selected) -> I.parse (Report.to_json v.report)) p.verification]) t.state_invariants)]))
let to_human (t : t) = Printf.sprintf "rbac-policy-sequence %s [%s]\nPhase: %s%s\n%s\n%s"
  (result_name t.outcome) (profile_id_for_version (version t)) (phase_name t.phase)
  (match t.failing_step with None -> "" | Some i ->
    if t.phase=State_invariants then Printf.sprintf "; state %d%s" i (if i=0 then " (baseline)" else " (after step)")
    else Printf.sprintf "; step %d" i) t.reason
  (match t.phase,t.failing_step with
   | Intermediate_preservation,Some i ->
     (match (List.find (fun p -> p.step=i) t.intermediate_preservation).verification with
      | Some v -> Report.to_human v.report | None -> "")
   | State_invariants,Some i ->
     (match (List.find (fun (p : invariant) -> p.state=i) t.state_invariants).verification with
      | Some v -> Report.to_human v.report | None -> "")
   | _ -> match t.comparison with None -> "Final access/preservation verification not executed.\n"
     | Some c -> Report.to_human c.report)
let exit_code (t : t) = match t.outcome with
  | Valid_sequence -> 0 | Unknown -> 4
  | Contract_failed -> (match t.comparison with Some {report={result=Vacuous;_};_}->5
      | Some {report={result=Inconsistent _;_};_}->6 | _->3)
  | Invariant_failed ->
    (match List.find_opt (fun (p : invariant) -> Some p.state=t.failing_step) t.state_invariants with
     | Some {verification=Some {report={result=Vacuous;_};_};_} -> 5
     | Some {verification=Some {report={result=Inconsistent _;_};_};_} -> 6
     | _ -> 3)
  | _ -> 3

let evidence_files provenance (t : t) =
  let* () = validate_evaluation t in
  let* spec = match t.spec with Some spec -> Ok spec | None -> Error "invalid sequence contract cannot produce frozen evidence" in
  let* nested = match t.comparison with
    | None -> Ok []
    | Some c ->
      let version=Contract_spec.version (Sequence_spec.requirements spec) in
      let profile : Evidence.profile = {id=Assurance.id_for_version version;json=Assurance.profile_json ~version ()} in
      let* bundle=Evidence.create_comparison ~before:t.before ~after:t.after ~profile ~provenance
        ~report:c.report ~candidate_report:c.candidate_report ~trace:c.trace in
      Ok (List.map (fun (path,data) -> "verification/"^path,data) (Evidence.files bundle)) in
  let state_files=List.mapi (fun index data -> Printf.sprintf "states/state-%03d.json" index,data) t.states in
  let preservation_files=List.concat_map (fun (p : intermediate) ->
    [Printf.sprintf "preservation/step-%03d.smt2" p.step,p.query] @
    match p.verification with None -> [] | Some v ->
      [Printf.sprintf "preservation/step-%03d-report.json" p.step,Report.to_json v.report^"\n"]) t.intermediate_preservation in
  let states=Array.of_list t.states in
  let rec invariant_files acc = function
    | [] -> Ok (List.concat (List.rev acc))
    | (p : invariant)::rest ->
      let prefix=Printf.sprintf "invariants/state-%03d/" p.state in
      let* files = match p.verification with
        | None -> Ok (("plan.json",I.json (`O ["state",number p.state;
            "input",digest states.(p.state);"status",str "not_executed";
            "queries",`A (List.map (fun (q : Contract_verify.obligation) ->
              `O ["id",str q.id;"path",str ("queries/"^q.id^".smt2")]) p.queries)])^"\n") ::
            List.map (fun (q : Contract_verify.obligation) -> "queries/"^q.id^".smt2",q.smtlib) p.queries)
        | Some v ->
          let version=Contract_spec.version (Sequence_spec.requirements spec) in
          let profile : Evidence.profile = {id=Assurance.id_for_version version;json=Assurance.profile_json ~version ()} in
          let* bundle=Evidence.create ~config:states.(p.state) ~profile ~provenance
            ~report:v.report ~trace:(Some v.trace) in
          Ok (Evidence.files bundle) in
      invariant_files (List.map (fun (path,data) -> prefix^path,data) files::acc) rest in
  let* invariant_files=invariant_files [] t.state_invariants in
  let files=["contract.json",Sequence_spec.canonical spec^"\n";
    "profile.json",profile_json_for_version (Sequence_spec.version spec)^"\n";
    "report.json",to_json t^"\n"] @ state_files @ preservation_files @ nested @ invariant_files in
  let manifest=I.json (`O (["schema_version",number (Sequence_spec.version spec);"kind",str "kubernetes-rbac-policy-sequence-evidence";
    "inputs",`O ["before",digest t.before;"after",digest t.after];
    "phase",str (phase_name t.phase);"failing_step",optional number t.failing_step;
    "authorization_method",str "deterministic-native-rbac-policy-coverage";
    "intermediate_preservation",`A (List.map (fun (p : intermediate) -> `O ["step",number p.step;
      "status",str (status p.verification);"query",str (Printf.sprintf "preservation/step-%03d.smt2" p.step);
      "report",(match p.verification with None -> `Null | Some _ -> str (Printf.sprintf "preservation/step-%03d-report.json" p.step))]) t.intermediate_preservation);
    "verification",str (if t.comparison=None then "not_executed" else "see verification/manifest.json");
    "provenance",`O ["executable_sha256",str provenance.Evidence.executable_sha256;
      "ocaml_version",str provenance.ocaml_version;"z3_version",(match provenance.z3_version with
        | Ok value -> `O ["value",str value] | Error reason -> `O ["error",str reason])];
    "artifacts",`A (List.map (fun (path,data) -> `O ["path",str path;"sha256",str (Sha256.string data);
      "bytes",number (String.length data)]) files)]
    @ if Sequence_spec.version spec=1 then [] else ["state_invariants",`A (List.map (fun (p : invariant) ->
      `O ["state",number p.state;"input",digest states.(p.state);"status",str (invariant_status p.verification);
        "verification",(match p.verification with None -> `Null
          | Some _ -> str (Printf.sprintf "invariants/state-%03d/manifest.json" p.state))]) t.state_invariants)])) in
  Ok (files @ ["manifest.json",manifest^"\n"])

let write_evidence ~directory t =
  let* provenance=Evidence.collect_provenance ?z3:t.z3 () in
  let* files=evidence_files provenance t in
  try
    Unix.mkdir directory 0o700;
    let rec parents path = if path="." then [] else parents (Filename.dirname path) @ [path] in
    let directories=List.concat_map (fun (path,_) -> parents (Filename.dirname path)) files
      |> List.sort_uniq String.compare in
    List.iter (fun path -> Unix.mkdir (Filename.concat directory path) 0o700) directories;
    List.iter (fun (relative,data) ->
      let target=Filename.concat directory relative in
      let manifest=Filename.basename relative="manifest.json" in
      let path=if manifest then target^".tmp" else target in
      let channel=open_out_gen [Open_wronly;Open_creat;Open_excl;Open_binary] 0o600 path in
      Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () -> output_string channel data;close_out channel);
      if manifest then begin Unix.link path target;Unix.unlink path end) files;
    Ok ()
  with Sys_error reason -> Error reason
    | Unix.Unix_error (error,operation,path) -> Error (Printf.sprintf "%s(%s): %s" operation path (Unix.error_message error))
