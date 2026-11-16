open Input

type t = { version : int; steps : Change_spec.t list; invariants : string list }
let kind = "kubernetes-rbac-policy-sequence"
let max_steps = 16
let has_kind source = match protect (fun () -> parse source) with
  | Ok (`O fields) -> List.assoc_opt "kind" fields=Some (`String kind)
  | _ -> false
let steps t = t.steps
let version t = t.version
let invariants t = t.invariants
let actor t = Change_spec.actor (List.hd t.steps)
let requirements t = Change_spec.requirements (List.hd t.steps)

let of_string source = protect (fun () ->
  let p = "sequence_contract" in
  let fields = obj p ["schema_version";"kind";"actor";"steps";"requirements";"invariants"] (parse source) in
  let version = match field p "schema_version" fields with
    | `Number "1" -> 1 | `Number "2" -> 2
    | _ -> reject p "schema_version must be integer 1 or 2" in
  if version=1 && List.mem_assoc "invariants" fields then reject p "invariants require schema 2";
  require_equal (p ^ ".kind") (string_field p "kind" fields) kind;
  let values = arr (p ^ ".steps") (field p "steps" fields) in
  if values=[] || List.length values>max_steps then reject (p ^ ".steps") "expected 1..16 steps";
  let seen = Hashtbl.create max_steps in
  let steps = List.mapi (fun index value ->
    let step_path = Printf.sprintf "%s.steps[%d]" p index in
    let step = obj step_path ["operation";"target"] value in
    let single = json (`O ["schema_version",`Number (string_of_int version);"kind",`String Change_spec.kind;
      "actor",field p "actor" fields;"operation",field step_path "operation" step;
      "target",field step_path "target" step;"requirements",field p "requirements" fields]) in
    let change = match Change_spec.of_string single with
      | Ok change -> change | Error reason -> reject step_path reason in
    let target = Change_spec.target change in
    let key = target.kind,target.namespace,target.name in
    if Hashtbl.mem seen key then reject step_path "duplicate target; each target may be written only once";
    Hashtbl.add seen key ();
    change) values in
  let invariants = if version=1 then [] else strings (p ^ ".invariants") (field p "invariants" fields) in
  let known = Contract_spec.clauses (Change_spec.requirements (List.hd steps))
    |> List.map (fun (c : Contract_spec.clause) -> c.name) in
  let seen = Hashtbl.create (List.length invariants) in
  List.iter (fun name ->
    if not (List.mem name known) then reject (p ^ ".invariants") (Printf.sprintf "unknown requirements clause %S" name);
    if Hashtbl.mem seen name then reject (p ^ ".invariants") (Printf.sprintf "duplicate clause name %S" name);
    Hashtbl.add seen name ()) invariants;
  {version;steps;invariants=List.sort String.compare invariants})

let canonical t =
  let step change = match parse (Change_spec.canonical change) with
    | `O fields -> `O ["operation",List.assoc "operation" fields;"target",List.assoc "target" fields]
    | _ -> assert false in
  json (`O (["schema_version",`Number (string_of_int t.version);"kind",`String kind;
    "actor",`String (actor t).username;"steps",`A (List.map step t.steps);
    "requirements",parse (Contract_spec.canonical (requirements t))]
    @ if t.version=1 then [] else ["invariants",`A (List.map (fun name -> `String name) t.invariants)]))

let frozen_spec t : Soundcheck_core.Report.frozen_spec =
  {schema_version=t.version;kind;canonical=canonical t}

let review t =
  Printf.sprintf "Frozen RBAC policy sequence (schema %d)\nActor: %S; trusted groups: [%s]\n%s\nAuthorization uses each immediately preceding state. Only the ordered distinct targets may change.\nEvery post-step state preserves original decisions outside the frozen change scope.\n%s\nConditional on each write succeeding and becoming visible before the next; no atomic deployment or concurrency guarantee.\nNested access contract: schema %d; preservation domain follows that schema.\n"
    t.version (actor t).username (String.concat ", " (List.map (Printf.sprintf "%S") (actor t).groups))
    (String.concat "\n" (List.mapi (fun index change ->
      let target = Change_spec.target change in
      Printf.sprintf "Step %d: %s %s namespace=%S name=%S" (index+1)
        (Change_spec.operation_name (Change_spec.operation change)) target.kind target.namespace target.name) t.steps))
    (if t.version=1 then "All access clauses apply at the final state; intermediate in-scope deviations are permitted."
     else "All access clauses apply at the final state. Selected invariant clauses must also hold at S0 and every post-step state: [" ^
       String.concat ", " (List.map (Printf.sprintf "%S") t.invariants) ^
       "]. Unselected final requirements may be violated at intermediate states inside scope. Delete-existing requires the named delete grant and complete visible removal before the next step; only default DELETE options are modeled.")
    (Contract_spec.version (requirements t))
