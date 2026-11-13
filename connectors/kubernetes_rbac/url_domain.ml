open Soundcheck_core

type selector = Exact of string | Prefix of string
let methods = ["get";"head";"post";"put";"patch";"delete";"options"]
let segment = Regex.Plus (Regex.Class (false,['a','z';'A','Z';'0','9';'-','-';'_','_';'.','.';'~','~']))
let tail = Regex.Concat [Regex.Star (Regex.Concat [Regex.Lit "/";segment]);Regex.Opt (Regex.Lit "/")]
let canonical = Regex.Alt [Regex.Lit "/";Regex.Concat [Regex.Lit "/";segment;tail]]
let dot_segment value = Regex.Concat [Regex.Star Regex.Any;Regex.Lit ("/"^value);
  Regex.Alt [Regex.Empty;Regex.Concat [Regex.Lit "/";Regex.Star Regex.Any]]]
let resource_paths = Regex.Alt [
  Regex.Concat [Regex.Lit "/api/";segment;Regex.Lit "/";segment;tail];
  Regex.Concat [Regex.Lit "/apis/";segment;Regex.Lit "/";segment;Regex.Lit "/";segment;tail]]

let path_condition = Ir.And [Ir.Path_regex canonical;
  Ir.Not (Ir.Path_regex (dot_segment "."));Ir.Not (Ir.Path_regex (dot_segment ".."));
  Ir.Not (Ir.Path_regex resource_paths)]

let condition = Ir.And [Ir.Not Ir.Has_object_request;path_condition;
  Ir.Or (List.map (fun method_ -> Ir.Method_is method_) methods)]

let canonical_path path = Regex.matches_full canonical path
  && not (Regex.matches_full (dot_segment ".") path)
  && not (Regex.matches_full (dot_segment "..") path)
let valid_path path = canonical_path path && not (Regex.matches_full resource_paths path)

let parse path value =
  let fields = Input.obj path ["exact";"prefix"] value in
  let literal key value =
    let value = Input.str (path^"."^key) value in
    if String.length value>2048 || not (canonical_path value) then
      Input.reject path "expected a canonical absolute ASCII path (at most 2048 bytes in a selector); no escaping, empty/dot segments, query or fragment";
    value in
  match fields with
  | ["exact",value] ->
    let value=literal "exact" value in
    if not (valid_path value) then Input.reject path "exact path is classified as a resource request by the pinned API server";
    Exact value
  | ["prefix",value] -> Prefix (literal "prefix" value)
  | _ -> Input.reject path "use exactly one paths selector: exact or prefix"

let selector_condition = function Exact value -> Ir.Path_exact value | Prefix value -> Ir.Path_prefix value
let json = function Exact value -> `O ["exact",`String value] | Prefix value -> `O ["prefix",`String value]
let describe = function Exact value -> Printf.sprintf "URL %S" value | Prefix value -> Printf.sprintf "URLs with prefix %S" value

(* Kubernetes URLMatches trims every trailing star. Interior stars remain
   literal, including ones that cannot occur in this canonical path domain. *)
let rule_condition value =
  let rec trim length = if length>0 && value.[length-1]='*' then trim (length-1) else length in
  let length=trim (String.length value) in
  if length<String.length value then Ir.Path_prefix (String.sub value 0 length)
  else Ir.Path_exact value
