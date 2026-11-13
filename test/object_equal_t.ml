open Soundcheck_core

let checks = ref 0
let check label condition = incr checks; if not condition then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason

let contains text fragment =
  let rec loop index =
    index + String.length fragment <= String.length text
    && (String.sub text index (String.length fragment) = fragment || loop (index + 1))
  in loop 0

let request object_request : Ir.request =
  {principal=Authenticated "alice";action="read";resource="";context=[];
   source=0l;host="";scheme="";sni="";object_request}

let equal = Ir.Object_equal (Object_namespace,Object_name)
let different = Ir.And [Has_object_request;Not equal]
let coordinates : Ir.object_request = {namespace="alpha";resource_kind="beta";name="alpha"}
let fixed = Ir.And [Object_is (Object_namespace,"alpha");
                    Object_is (Object_kind,"beta");Object_is (Object_name,"alpha")]

let query ?(domain=Ir.True) condition =
  Smt_encode.condition_query ~domain ~name:"object equality" ~description:"coordinate relation" condition

let sat ?(domain=Ir.True) label condition =
  match Solve.check (query ~domain condition)
        |> Witness.validate ~obligation:label (Witness.condition ~domain condition) with
  | Solve.Violated model -> incr checks; model
  | result -> failwith (label ^ ": " ^ Solve.string_of_result result)

let unsat label condition = check label (Solve.check (query condition)=Solve.Proved)

let concrete_and_smt () =
  (* Each tuple is an independent concrete field fixture. Compare every ordered
     pair, including same-field and empty-string equality, not just the pair a
     particular connector uses. *)
  let fixtures = [
    "all distinct",("a","b","c");
    "all equal",("same","same","same");
    "namespace/name equal",("alpha","beta","alpha");
    "namespace/kind equal",("alpha","alpha","beta");
    "kind/name equal",("alpha","beta","beta");
    "empty strings",("","","");
    "one empty",("","value","value");
    "case sensitive",("Case","case","Case");
    "exact bytes",("\x00\xc3\xa9","\x00\xc3\xa9","\xc3\xa9") ] in
  let fields = Ir.[Object_namespace;Object_kind;Object_name] in
  List.iter (fun (label,(namespace,resource_kind,name)) ->
      let obj : Ir.object_request = {namespace;resource_kind;name} in
      let values = [namespace;resource_kind;name] in
      List.iteri (fun i left -> List.iteri (fun j right ->
          let predicate = Ir.Object_equal (left,right) in
          let expected = List.nth values i = List.nth values j in
          check (label ^ " concrete") (Ir.matches predicate (request (Some obj))=expected);
          check (label ^ " absent") (not (Ir.matches predicate (request None)))) fields) fields) fixtures;
  (* Pin unequal coordinates before negating the independently known answer.
     This catches swapped field symbols and a presence guard omitted in SMT. *)
  List.iteri (fun i left -> List.iteri (fun j right ->
      let predicate = Ir.Object_equal (left,right) in
      let expected = i=j || (i=0 && j=2) || (i=2 && j=0) in
      unsat "fixed concrete/SMT relation"
        (Ir.And [fixed;(if expected then Ir.Not predicate else predicate)]);
      unsat "SMT absent equality" Ir.(And [Not Has_object_request;predicate]);
      unsat "SMT symmetry" Ir.(And [predicate;Not (Object_equal (right,left))])) fields) fields;
  let absent = sat "negated equality permits absent coordinates" Ir.(And [Not Has_object_request;Not equal]) in
  check "absent stays absent after decoding" (absent.object_request=None);
  (* Probe the SMT representation directly: inactive strings cannot carry
     arbitrary Unicode, whereas the same nonempty byte values remain legal on
     a present object. This must not relax malformed-model decoding. *)
  List.iter (fun symbol ->
      let source = query Ir.(Not Has_object_request) in
      let marker = "(check-sat)" in
      let rec index n = if String.sub source n (String.length marker)=marker then n else index (n+1) in
      let n=index 0 in
      let constrained = String.sub source 0 n ^
        Printf.sprintf "(assert (not (= %s \"\")))\n" symbol ^
        String.sub source n (String.length source-n) in
      check "absent coordinate has one representation" (Solve.check constrained=Solve.Proved))
    ["object_namespace";"object_kind";"object_name"];
  let empty = sat "empty fields are present and equal"
      Ir.(And [equal;Object_is (Object_namespace,"");Object_is (Object_name,"")]) in
  check "empty equal values retain object presence" (Option.is_some empty.object_request);
  List.iter (fun field ->
      ignore (sat "same-field equality requires an object" (Ir.Object_equal (field,field)));
      unsat "present field cannot differ from itself"
        Ir.(And [Has_object_request;Not (Object_equal (field,field))])) fields;
  ignore (sat "unequal coordinates are satisfiable" different);
  unsat "equality and inequality conflict" (Ir.And [equal;different]);
  unsat "coordinate equality is transitive"
    Ir.(And [Object_equal (Object_namespace,Object_kind);
             Object_equal (Object_kind,Object_name);Not equal]);
  let bytes = "\x00\xc3\xa9" in
  let byte_model = sat "equality retains exact bytes"
      Ir.(And [equal;Object_is (Object_namespace,bytes)]) in
  check "equality is not textual normalization"
    (Option.fold ~none:false ~some:(fun (obj : Ir.object_request) -> obj.name=bytes) byte_model.object_request)

let witnesses_and_domains () =
  (* Equality alone must request all typed observations. No other object
     predicate or named identity can accidentally enable that traversal. *)
  let model = sat "bare equality" equal in
  check "bare equality has no fabricated identity" (model.principal_name=None);
  check "bare equality has typed coordinates" (Option.is_some model.object_request);
  ignore (sat "nested equality traversal" (Ir.Not (Ir.Or [Ir.Not equal])));
  let model = sat ~domain:equal "equality in request domain" fixed in
  check "domain constrained witness" (model.object_request=Some coordinates);
  let validate candidate =
    Witness.validate ~obligation:"domain equality"
      (Witness.condition ~domain:equal Ir.True) (Solve.Violated candidate) in
  check "mismatched witness rejected"
    (match validate {model with object_request=Some {coordinates with name="other"}} with
     | Solve.Unknown _ -> true | _ -> false);
  check "absent witness rejected"
    (match validate {model with object_request=None} with Solve.Unknown _ -> true | _ -> false);
  check "domain accepts equal coordinates" (Witness.condition ~domain:equal Ir.True (request (Some coordinates)));
  check "domain rejects unequal coordinates"
    (not (Witness.condition ~domain:equal Ir.True (request (Some {coordinates with name="other"}))));
  check "domain rejects absent coordinates" (not (Witness.condition ~domain:equal Ir.True (request None)))

let rule ?(guard=Ir.True) condition : Ir.rule =
  {id="allow";match_=condition;match_complete=true;guard;guard_complete=true;
   priority={comparable=true;key=[]};decision=Allow;rate_limited=false;targets_admin=false}

let policy ?(domain=Ir.True) rules : Ir.policy = {request_domain=domain;rules;default=Deny}

let integration () =
  let allow = policy ~domain:equal [rule Ir.True] and deny = policy ~domain:equal [] in
  let difference = Smt_encode.decision_equivalence_query deny allow |> Solve.check
    |> Witness.validate ~obligation:"equality domain comparison" (Witness.decision_difference deny allow) in
  check "comparison retains relational-domain witness"
    (match difference with Solve.Violated model ->
       Option.is_some model.object_request && Ir.matches equal (Witness.request_of_model model)
     | _ -> false);
  let property : Property.t =
    {name="relation";description="relation";forbidden_when=True;reach_via=(fun _ -> true)} in
  List.iter (fun p ->
      let result = Solve.check (Smt_encode.to_smtlib p property)
        |> Witness.validate ~obligation:"equality allowance" (Witness.property p property) in
      check "rule/guard equality observations retained"
        (match result with Solve.Violated model ->
           Option.is_some model.object_request && Ir.matches equal (Witness.request_of_model model)
         | _ -> false))
    [policy [rule equal];policy [rule ~guard:equal Ir.True]];
  let contract : Contract.t =
    {name="relation";description="coordinate relation";
     clauses=[Contract.must_allow ~name:"same" ~description:"equal coordinates" equal;
              Contract.must_deny ~name:"different" ~description:"unequal coordinates" different]} in
  check "paired relational contract proves"
    (Contract_verify.run (policy [rule equal]) contract=Contract_verify.Proved);
  check "broad grant violates relational prohibition"
    (match Contract_verify.run (policy [rule Ir.Has_object_request]) contract with
     | Contract_verify.Violated (_,model) -> Ir.matches different (Witness.request_of_model model)
     | _ -> false);
  let evidence_policy = policy ~domain:fixed [rule equal] in
  let evidence_contract = {contract with clauses=[List.hd contract.clauses]} in
  let verdict,trace = Contract_verify.run_with_trace evidence_policy evidence_contract in
  check "evidence source run proves" (verdict=Contract_verify.Proved);
  let profile : Evidence.profile = {id="object-equality-test";json="{\"id\":\"object-equality-test\"}"} in
  let report : Report.t =
    {result=Proved;property_name="relation";property_description="coordinate relation";
     assurance=Some {profile=profile.id;status=Within_profile;findings=[]};clause=None;
     frozen_spec=Some {schema_version=1;kind="relation";canonical="{\"kind\":\"relation\"}"}} in
  let provenance : Evidence.provenance =
    {executable_sha256=String.make 64 'a';ocaml_version="test";z3_version=Ok "test"} in
  let bundle = Evidence.create ~config:"equality policy" ~profile ~provenance ~report ~trace:(Some trace) |> ok in
  let files = Evidence.files bundle in
  check "evidence keeps related coordinate values"
    (contains (List.assoc "manifest.json" files)
       "\"object_request\":{\"namespace\":\"alpha\",\"resource_kind\":\"beta\",\"name\":\"alpha\"}");
  List.iter (fun (row : Contract_verify.trace_entry) ->
      let source = List.assoc ("queries/" ^ row.obligation.id ^ ".smt2") files in
      check "evidence retains exact equality query" (source=row.obligation.smtlib);
      check "equality remains replayable in evidence"
        (contains source "(= object_namespace object_name)")) trace

let () =
  concrete_and_smt ();
  witnesses_and_domains ();
  integration ();
  Printf.printf "%d generic object equality checks passed\n" !checks
