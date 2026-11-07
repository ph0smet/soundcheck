(* Presentation of a verification result. Both serializers live here so every
   adapter renders identically — see report.mli. *)

type counterexample = {
  principal        : string;
  action           : string;
  path             : string;
  route            : string option;
  service          : string option;
  shadowed_route   : string option;
  shadowed_service : string option;
  host             : string;
  scheme           : string;
  sni              : string;
  source_ip        : int32;
  headers          : (string * string) list;
  object_request   : Ir.object_request option;
  identity_groups  : string list option;
  granting_rules   : string list;
  note             : string;
}

type clause_kind = Must_deny | Must_allow | Must_not_grant | Must_preserve

type clause = {
  name        : string;
  description : string;
  kind        : clause_kind;
}

type frozen_spec = {
  schema_version : int;
  kind           : string;
  canonical      : string;
}

type assurance_status = Within_profile | Conservative | Unsupported

type assurance_finding = {
  code    : string;
  service : string option;
  route   : string option;
  detail  : string;
}

type assurance = {
  profile  : string;
  status   : assurance_status;
  findings : assurance_finding list;
}

type outcome =
  | Proved
  | Vacuous
  | Inconsistent of string
  | Violated of counterexample
  | Unknown of string

type t = {
  result               : outcome;
  property_name        : string;
  property_description  : string;
  assurance             : assurance option;
  clause               : clause option;
  frozen_spec          : frozen_spec option;
}

(* --- human --- *)

let to_human t =
  let verdict =
    match t.result with
    | Proved ->
      Printf.sprintf "PROVED   %s\n         %s" t.property_name t.property_description
    | Vacuous ->
      Printf.sprintf
        "VACUOUS  %s\n         %s\n         The property's forbidden request class is empty; no config was verified."
        t.property_name t.property_description
    | Inconsistent reason ->
      Printf.sprintf "INCONSISTENT %s\n             %s" t.property_name reason
    | Violated ce ->
      Printf.sprintf "VIOLATED %s\n         %s" t.property_name ce.note
    | Unknown reason ->
      Printf.sprintf "UNKNOWN  %s" reason
  in
  let with_assurance =
    match t.assurance with
    | None -> verdict
    | Some assurance ->
      let status =
        match assurance.status with
        | Within_profile -> "within_profile"
        | Conservative -> "conservative"
        | Unsupported -> "unsupported"
      in
      let header =
        Printf.sprintf "%s\n         Assurance: %s (%s)" verdict assurance.profile status
      in
      List.fold_left
        (fun text finding ->
          Printf.sprintf "%s\n         - %s: %s" text finding.code finding.detail)
        header assurance.findings
  in
  match t.frozen_spec with
  | None -> with_assurance
  | Some spec ->
    Printf.sprintf "%s\n         Frozen spec: %s" with_assurance spec.canonical

(* --- json (hand-rolled: schema is small and flat) --- *)

(* Escape a string per RFC 8259 so the emitted document is always valid JSON. *)
let escape s =
  let buf = Buffer.create (String.length s + 2) in
  String.iter
    (fun c ->
      match c with
      | '"'  -> Buffer.add_string buf "\\\""
      | '\\' -> Buffer.add_string buf "\\\\"
      | '\n' -> Buffer.add_string buf "\\n"
      | '\r' -> Buffer.add_string buf "\\r"
      | '\t' -> Buffer.add_string buf "\\t"
      | c when Char.code c < 0x20 ->
        Buffer.add_string buf (Printf.sprintf "\\u%04x" (Char.code c))
      | c -> Buffer.add_char buf c)
    s;
  Buffer.contents buf

let jstring s = "\"" ^ escape s ^ "\""

(* A JSON string, or null for an absent connector field. *)
let jopt = function
  | Some s -> jstring s
  | None   -> "null"

(* Bumped when the shape changes in a way a consumer must notice. Adding an
   always-present field counts; every key below is emitted unconditionally
   (null when absent) so a consumer never has to probe for existence. *)
let schema_version = 10

let object_request_json = function
  | None -> "null"
  | Some (request : Ir.object_request) ->
    Printf.sprintf "{\"namespace\":%s,\"resource_kind\":%s,\"name\":%s}"
      (jstring request.namespace) (jstring request.resource_kind) (jstring request.name)

let string_array_json values =
  "[" ^ String.concat "," (List.map jstring values) ^ "]"

let counterexample_json ce =
  let headers =
    ce.headers
    |> List.map (fun (name, value) ->
           Printf.sprintf "{\"name\":%s,\"value\":%s}"
             (jstring name) (jstring value))
    |> String.concat ","
  in
  Printf.sprintf
    "{\"principal\":%s,\"action\":%s,\"path\":%s,\"host\":%s,\"scheme\":%s,\"sni\":%s,\"headers\":[%s],\"source_ip\":%s,\"route\":%s,\"service\":%s,\"shadowed_route\":%s,\"shadowed_service\":%s,\"object_request\":%s,\"identity_groups\":%s,\"granting_rules\":%s}"
    (jstring ce.principal) (jstring ce.action) (jstring ce.path) (jstring ce.host)
    (jstring ce.scheme) (jstring ce.sni) headers
    (jstring (Cidr.string_of_ip ce.source_ip))
    (jopt ce.route) (jopt ce.service)
    (jopt ce.shadowed_route) (jopt ce.shadowed_service)
    (object_request_json ce.object_request)
    (match ce.identity_groups with None -> "null" | Some groups -> string_array_json groups)
    (string_array_json ce.granting_rules)

let clause_json = function
  | None -> "null"
  | Some (clause : clause) ->
    let kind = match clause.kind with
      | Must_deny -> "must_deny" | Must_allow -> "must_allow"
      | Must_not_grant -> "must_not_grant" | Must_preserve -> "must_preserve" in
    Printf.sprintf "{\"name\":%s,\"description\":%s,\"kind\":%s}"
      (jstring clause.name) (jstring clause.description) (jstring kind)

let frozen_spec_json = function
  | None -> "null"
  | Some spec ->
    Printf.sprintf "{\"schema_version\":%d,\"kind\":%s,\"canonical\":%s}"
      spec.schema_version (jstring spec.kind) (jstring spec.canonical)

let assurance_status_string = function
  | Within_profile -> "within_profile"
  | Conservative -> "conservative"
  | Unsupported -> "unsupported"

let assurance_finding_json finding =
  Printf.sprintf "{\"code\":%s,\"service\":%s,\"route\":%s,\"detail\":%s}"
    (jstring finding.code) (jopt finding.service) (jopt finding.route)
    (jstring finding.detail)

let assurance_json = function
  | None -> "null"
  | Some assurance ->
    let findings =
      assurance.findings |> List.map assurance_finding_json |> String.concat ","
    in
    Printf.sprintf "{\"profile\":%s,\"status\":%s,\"findings\":[%s]}"
      (jstring assurance.profile)
      (jstring (assurance_status_string assurance.status)) findings

let to_json t =
  let prop = jstring t.property_name in
  let head =
    Printf.sprintf
      "\"schema_version\":%d,\"property\":%s,\"assurance\":%s,\"frozen_spec\":%s,\"clause\":%s"
      schema_version prop (assurance_json t.assurance)
      (frozen_spec_json t.frozen_spec) (clause_json t.clause)
  in
  match t.result with
  | Proved ->
    Printf.sprintf "{\"result\":\"proved\",%s,\"counterexample\":null}" head
  | Vacuous ->
    Printf.sprintf "{\"result\":\"vacuous\",%s,\"counterexample\":null}" head
  | Inconsistent reason ->
    Printf.sprintf
      "{\"result\":\"inconsistent\",%s,\"counterexample\":null,\"reason\":%s}"
      head (jstring reason)
  | Violated ce ->
    Printf.sprintf "{\"result\":\"violated\",%s,\"counterexample\":%s}" head
      (counterexample_json ce)
  | Unknown reason ->
    Printf.sprintf
      "{\"result\":\"unknown\",%s,\"counterexample\":null,\"reason\":%s}" head
      (jstring reason)
