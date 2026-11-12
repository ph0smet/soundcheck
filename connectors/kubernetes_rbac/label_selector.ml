open Input

type requirement = In of string * string list | Not_in of string * string list
  | Exists of string | Absent of string
type t = { requirements : requirement list; cost : int }

let key path value =
  let value = str path value in
  if not (qualified_name value) then reject path "invalid label selector key";
  value

let label_value path value =
  let value = str path value in
  if value <> "" && not (qualified_part value) then reject path "invalid label selector value";
  value

let parse path value =
  let fields = obj path ["matchLabels";"matchExpressions"] value in
  let labels = match List.assoc_opt "matchLabels" fields with
    | None | Some `Null -> []
    | Some value ->
      metadata_map (path ^ ".matchLabels") ~annotations:false value;
      (match value with
       | `O pairs -> List.map (fun (key,value) -> In (key,[str path value])) pairs
       | _ -> assert false) in
  let expressions = optional_list path "matchExpressions" fields in
  let cost = ref (1 + List.length labels) in
  let expressions = List.mapi (fun index value ->
    let path = Printf.sprintf "%s.matchExpressions[%d]" path index in
    let fields = obj path ["key";"operator";"values"] value in
    let key = key (path ^ ".key") (field path "key" fields) in
    let values = optional_list path "values" fields
      |> List.mapi (fun i -> label_value (Printf.sprintf "%s.values[%d]" path i)) in
    cost := !cost + 1 + List.length values;
    match string_field path "operator" fields with
    | "In" when values <> [] -> In (key,values)
    | "NotIn" when values <> [] -> Not_in (key,values)
    | "Exists" when values = [] -> Exists key
    | "DoesNotExist" when values = [] -> Absent key
    | "In" | "NotIn" -> reject (path ^ ".values") "In and NotIn require at least one value"
    | "Exists" | "DoesNotExist" -> reject (path ^ ".values") "Exists and DoesNotExist require no values"
    | _ -> reject (path ^ ".operator") "expected In, NotIn, Exists or DoesNotExist") expressions in
  {requirements=labels @ expressions;cost= !cost}

let cost selector = selector.cost
let matches selector lookup = List.for_all (function
  | In (key,values) -> (match lookup key with Some value -> List.mem value values | None -> false)
  | Not_in (key,values) -> (match lookup key with Some value -> not (List.mem value values) | None -> true)
  | Exists key -> Option.is_some (lookup key)
  | Absent key -> Option.is_none (lookup key)) selector.requirements
