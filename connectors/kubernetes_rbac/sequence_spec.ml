open Input

type t = { steps : Change_spec.t list }
let kind = "kubernetes-rbac-policy-sequence"
let max_steps = 16
let has_kind source = match protect (fun () -> parse source) with
  | Ok (`O fields) -> List.assoc_opt "kind" fields=Some (`String kind)
  | _ -> false
let steps t = t.steps
let actor t = Change_spec.actor (List.hd t.steps)
let requirements t = Change_spec.requirements (List.hd t.steps)

let of_string source = protect (fun () ->
  let p = "sequence_contract" in
  let fields = obj p ["schema_version";"kind";"actor";"steps";"requirements"] (parse source) in
  if field p "schema_version" fields <> `Number "1" then reject p "schema_version must be integer 1";
  require_equal (p ^ ".kind") (string_field p "kind" fields) kind;
  let values = arr (p ^ ".steps") (field p "steps" fields) in
  if values=[] || List.length values>max_steps then reject (p ^ ".steps") "expected 1..16 steps";
  let seen = Hashtbl.create max_steps in
  let steps = List.mapi (fun index value ->
    let step_path = Printf.sprintf "%s.steps[%d]" p index in
    let step = obj step_path ["operation";"target"] value in
    let single = json (`O ["schema_version",`Number "1";"kind",`String Change_spec.kind;
      "actor",field p "actor" fields;"operation",field step_path "operation" step;
      "target",field step_path "target" step;"requirements",field p "requirements" fields]) in
    let change = match Change_spec.of_string single with
      | Ok change -> change | Error reason -> reject step_path reason in
    let target = Change_spec.target change in
    let key = target.kind,target.namespace,target.name in
    if Hashtbl.mem seen key then reject step_path "duplicate target; each target may be written only once";
    Hashtbl.add seen key ();
    change) values in
  {steps})

let canonical t =
  let step change = match parse (Change_spec.canonical change) with
    | `O fields -> `O ["operation",List.assoc "operation" fields;"target",List.assoc "target" fields]
    | _ -> assert false in
  json (`O ["schema_version",`Number "1";"kind",`String kind;
    "actor",`String (actor t).username;"steps",`A (List.map step t.steps);
    "requirements",parse (Contract_spec.canonical (requirements t))])

let review t =
  Printf.sprintf "Frozen RBAC policy sequence (schema 1)\nActor: %S; trusted groups: [%s]\n%s\nAuthorization uses each immediately preceding state. Only the ordered distinct targets may change.\nEvery post-step state preserves original decisions outside the frozen change scope.\nAll access clauses apply at the final state; intermediate in-scope deviations are permitted.\nConditional on each write succeeding and becoming visible before the next; no atomic deployment or concurrency guarantee.\nNested access contract: schema %d; preservation domain follows that schema.\n"
    (actor t).username (String.concat ", " (List.map (Printf.sprintf "%S") (actor t).groups))
    (String.concat "\n" (List.mapi (fun index change ->
      let target = Change_spec.target change in
      Printf.sprintf "Step %d: %s %s namespace=%S name=%S" (index+1)
        (Change_spec.operation_name (Change_spec.operation change)) target.kind target.namespace target.name) t.steps))
    (Contract_spec.version (requirements t))
