open Soundcheck_core

(* Independent finite target worlds, not an encoder/evaluator agreement test.

   Each abstract predicate is an upper bound [may], with an optional exactness
   guarantee. A concrete refinement may turn an incomplete true predicate into
   false, but may never turn an abstract false into true. Concrete routing picks
   one highest matching rule; incomparable/tied priorities admit either winner.
   A selected rule's failing guard denies instead of rerouting or falling back.

   The oracle below uses these booleans and a separate ordering implementation;
   it does not call [Ir.selected], [Ir.outranks], or the SMT encoder. *)
type predicate = { may : bool; complete : bool; actual : bool }

type refinement = {
  abstract_rule : Ir.rule;
  matching : predicate;
  guard : predicate;
}

let predicates =
  [ { may = false; complete = false; actual = false };
    { may = false; complete = true; actual = false };
    { may = true; complete = false; actual = false };
    { may = true; complete = false; actual = true };
    { may = true; complete = true; actual = true } ]

let priorities : Ir.priority list =
  [ { comparable = true; key = [ 0 ] };
    { comparable = true; key = [ 1 ] };
    { comparable = false; key = [ 1 ] };
    { comparable = true; key = [ 1; 0 ] } ]

let condition = function true -> Ir.True | false -> Ir.Or []

let refinements id =
  List.concat_map
    (fun matching ->
      List.concat_map
        (fun guard ->
          List.concat_map
            (fun decision ->
              List.map
                (fun priority ->
                  { abstract_rule =
                      { Ir.id; match_ = condition matching.may;
                        match_complete = matching.complete;
                        guard = condition guard.may;
                        guard_complete = guard.complete; priority; decision;
                        rate_limited = false; targets_admin = false };
                    matching; guard })
                priorities)
            [ Ir.Allow; Ir.Deny ])
        predicates)
    predicates

let rec strict_lexicographic left right =
  match left, right with
  | x :: xs, y :: ys ->
    if x = y then strict_lexicographic xs ys else x > y
  | _ -> false

let concrete_outranks (left : Ir.priority) (right : Ir.priority) =
  left.comparable && right.comparable
  && List.length left.key = List.length right.key
  && strict_lexicographic left.key right.key

let actual_outcomes ~default left right =
  let matching = List.filter (fun r -> r.matching.actual) [ left; right ] in
  let winners =
    List.filter
      (fun candidate ->
        not (List.exists
          (fun other -> concrete_outranks other.abstract_rule.priority
                          candidate.abstract_rule.priority)
          matching))
      matching
  in
  match winners with
  | [] -> [ default = Ir.Allow ]
  | _ ->
    List.map
      (fun winner -> winner.abstract_rule.decision = Ir.Allow && winner.guard.actual)
      winners

let request : Ir.request =
  { principal = Anonymous; action = "GET"; resource = "/";
    context = []; source = 0l; host = "example.test"; scheme = "http"; sni = "" }

(* Deliberately broken controls demonstrate what the independent oracle catches.
   Merely allowing the default too often is still a may overapproximation, so
   exact deterministic worlds additionally require exact may/must answers. *)
let mutant_may ?(deny_overrides = false) ?(unconditional_default = false)
    ?(incomplete_suppression = false) ?(mixed_priority_shapes = false)
    ~default left right =
  let rules = [ left; right ] in
  let outranks (a : Ir.priority) (b : Ir.priority) =
    if mixed_priority_shapes then
      a.comparable && b.comparable && strict_lexicographic a.key b.key
    else concrete_outranks a b
  in
  let selected rule =
    rule.matching.may
    && not (List.exists
      (fun other ->
        (incomplete_suppression || other.matching.complete)
        && other.matching.may
        && outranks other.abstract_rule.priority rule.abstract_rule.priority)
      rules)
  in
  let matched decision =
    List.exists (fun r -> r.abstract_rule.decision = decision
                          && selected r && r.guard.may) rules
  in
  let fallback =
    default = Ir.Allow
    && (unconditional_default
        || not (List.exists (fun r -> r.matching.complete && r.matching.may) rules))
  in
  (matched Ir.Allow || fallback)
  && (not deny_overrides || not (matched Ir.Deny))

let describe name left right default actual may must =
  let rule r =
    Printf.sprintf
      "match(may=%b exact=%b actual=%b) guard(may=%b exact=%b actual=%b) %s rank=%s/%b"
      r.matching.may r.matching.complete r.matching.actual
      r.guard.may r.guard.complete r.guard.actual
      (Ir.string_of_decision r.abstract_rule.decision)
      (String.concat "," (List.map string_of_int r.abstract_rule.priority.key))
      r.abstract_rule.priority.comparable
  in
  Printf.sprintf "%s: [%s] [%s] default=%s actual=%b may=%b must=%b"
    name (rule left) (rule right) (Ir.string_of_decision default) actual may must

let () =
  let worlds = ref 0 and exact_worlds = ref 0 in
  let controls =
    [ ("deny-overrides",
       (fun ~default left right -> mutant_may ~deny_overrides:true ~default left right),
       ref 0);
      ("default-Allow fallthrough",
       (fun ~default left right -> mutant_may ~unconditional_default:true ~default left right),
       ref 0);
      ("incomplete suppressor",
       (fun ~default left right -> mutant_may ~incomplete_suppression:true ~default left right),
       ref 0);
      ("mixed priority shapes",
       (fun ~default left right -> mutant_may ~mixed_priority_shapes:true ~default left right),
       ref 0) ]
  in
  List.iter
    (fun left ->
      List.iter
        (fun right ->
          List.iter
            (fun default ->
              let policy : Ir.policy =
                { request_domain = True;
                  rules = [ left.abstract_rule; right.abstract_rule ]; default }
              in
              let outcomes = actual_outcomes ~default left right in
              let exact =
                List.for_all (fun r -> r.matching.complete && r.guard.complete)
                  [ left; right ]
                && List.length (List.sort_uniq Bool.compare outcomes) = 1
              in
              let may = Ir.possibly_allows policy request in
              let must = Ir.definitely_allows policy request in
              List.iter
                (fun actual ->
                  incr worlds;
                  if exact then incr exact_worlds;
                  if (actual && not may) || (must && not actual)
                     || (exact && (may <> actual || must <> actual))
                  then failwith (describe "refinement bound" left right default actual may must);
                  if Ir.evaluate policy request <> (if may then Ir.Allow else Ir.Deny)
                  then failwith "evaluate does not expose the may allowance";
                  List.iter
                    (fun (_, mutant, failures) ->
                      let bad_may = mutant ~default left right in
                      if (actual && not bad_may) || (exact && bad_may <> actual)
                      then incr failures)
                    controls)
                outcomes)
            [ Ir.Allow; Ir.Deny ])
        (refinements "right"))
    (refinements "left");
  if !worlds <> 91_200 then
    failwith (Printf.sprintf "refinement world count changed: %d" !worlds);
  if !exact_worlds = 0 then failwith "no exact-world controls were exercised";
  List.iter
    (fun (name, _, failures) ->
      if !failures = 0 then failwith ("oracle missed deliberately broken " ^ name);
      Printf.printf "[ok] oracle rejects %s (%d worlds)\n" name !failures)
    controls;
  Printf.printf
    "independent refinement oracle: %d worlds, %d exact worlds, no failures\n"
    !worlds !exact_worlds
