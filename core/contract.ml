type clause =
  | Must_deny of {
      name           : string;
      description    : string;
      forbidden_when : Ir.condition;
      reach_via      : Ir.rule -> bool;
    }
  | Must_allow of {
      name          : string;
      description   : string;
      required_when : Ir.condition;
    }

type t = {
  name        : string;
  description : string;
  clauses     : clause list;
}

let must_deny ?(reach_via = fun _ -> true) ~name ~description forbidden_when =
  Must_deny { name; description; forbidden_when; reach_via }

let must_allow ~name ~description required_when =
  Must_allow { name; description; required_when }

let request_class = function
  | Must_deny c -> c.forbidden_when
  | Must_allow c -> c.required_when

let name = function
  | Must_deny c -> c.name
  | Must_allow c -> c.name

let description = function
  | Must_deny c -> c.description
  | Must_allow c -> c.description

let safety_functionality_overlaps contract =
  let safety =
    List.filter_map
      (function Must_deny _ as clause -> Some clause | Must_allow _ -> None)
      contract.clauses
  in
  let functionality =
    List.filter_map
      (function Must_allow _ as clause -> Some clause | Must_deny _ -> None)
      contract.clauses
  in
  List.concat_map
    (fun must_deny -> List.map (fun must_allow -> (must_deny, must_allow)) functionality)
    safety
