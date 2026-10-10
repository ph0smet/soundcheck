type result =
  | Proved
  | Vacuous of Contract.clause
  | Inconsistent of Contract.clause * Contract.clause
  | Violated of Contract.clause * Solve.model
  | Unknown of string

type phase = Inhabitance | Consistency | Clause

type obligation = {
  id      : string;
  phase   : phase;
  clauses : string list;
  smtlib  : string;
}

type execution = Not_executed | Executed of Solve.result

type trace_entry = {
  obligation : obligation;
  execution  : execution;
}

type planned = {
  public : obligation;
  satisfies : Ir.request -> bool;
  decide : Solve.result -> result option;
}

let slug value =
  let buffer = Buffer.create (String.length value) in
  let separator = ref false in
  String.iter
    (function
      | ('a' .. 'z' | '0' .. '9') as character ->
        if !separator && Buffer.length buffer > 0 then Buffer.add_char buffer '-';
        separator := false;
        Buffer.add_char buffer character
      | 'A' .. 'Z' as character ->
        if !separator && Buffer.length buffer > 0 then Buffer.add_char buffer '-';
        separator := false;
        Buffer.add_char buffer (Char.lowercase_ascii character)
      | _ -> separator := true)
    value;
  if Buffer.length buffer = 0 then "unnamed" else Buffer.contents buffer

let obligation_id phase index names =
  Printf.sprintf "%s-%02d-%s" phase (index + 1)
    (String.concat "-" (List.map slug names))

let planned (policy : Ir.policy) (contract : Contract.t) =
  let inhabitance =
    List.mapi
      (fun index clause ->
        let name = Contract.name clause in
        { public =
            { id = obligation_id "inhabitance" index [ name ];
              phase = Inhabitance;
              clauses = [ name ];
              smtlib =
                Smt_encode.condition_query ~domain:policy.request_domain
                  ~name ~description:(Contract.description clause)
                  (Contract.request_class clause) };
          satisfies = Witness.condition ~domain:policy.request_domain
              (Contract.request_class clause);
          decide =
            (function
              | Solve.Proved -> Some (Vacuous clause)
              | Solve.Unknown reason -> Some (Unknown reason)
              | Solve.Violated _ -> None) })
      contract.clauses
  in
  let consistency =
    Contract.safety_functionality_overlaps contract
    |> List.mapi (fun index (safety, functionality) ->
           let names = [ Contract.name safety; Contract.name functionality ] in
           { public =
               { id = obligation_id "consistency" index names;
                 phase = Consistency;
                 clauses = names;
                 smtlib =
                   Smt_encode.overlap_query ~domain:policy.request_domain safety
                     functionality };
             satisfies = Witness.condition ~domain:policy.request_domain
                 (Ir.And [Contract.request_class safety;
                          Contract.request_class functionality]);
             decide =
               (function
                 | Solve.Violated _ -> Some (Inconsistent (safety, functionality))
                 | Solve.Unknown reason -> Some (Unknown reason)
                 | Solve.Proved -> None) })
  in
  let clauses =
    List.mapi
      (fun index clause ->
        let name = Contract.name clause in
        { public =
            { id = obligation_id "clause" index [ name ];
              phase = Clause;
              clauses = [ name ];
              smtlib = Smt_encode.contract_clause_query policy clause };
          satisfies = Witness.clause policy clause;
          decide =
            (function
              | Solve.Violated model -> Some (Violated (clause, model))
              | Solve.Unknown reason -> Some (Unknown reason)
              | Solve.Proved -> None) })
      contract.clauses
  in
  inhabitance @ consistency @ clauses

let plan policy contract =
  planned policy contract |> List.map (fun item -> item.public)

let run_with_trace ?z3 policy contract =
  let rec execute checked = function
    | [] -> (Proved, List.rev checked)
    | item :: rest ->
      let solver_result =
        Solve.check ?z3 item.public.smtlib
        |> Witness.validate ~obligation:item.public.id item.satisfies
      in
      let entry = { obligation = item.public; execution = Executed solver_result } in
      (match item.decide solver_result with
       | None -> execute (entry :: checked) rest
       | Some result ->
         let skipped =
           List.map
             (fun item ->
               { obligation = item.public; execution = Not_executed })
             rest
         in
         (result, List.rev checked @ (entry :: skipped)))
  in
  execute [] (planned policy contract)

let run ?z3 policy contract = fst (run_with_trace ?z3 policy contract)
