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
  source_ip        : int32;
  note             : string;
}

type outcome =
  | Proved
  | Vacuous
  | Violated of counterexample
  | Unknown of string

type t = {
  result               : outcome;
  property_name        : string;
  property_description  : string;
}

(* --- human --- *)

let to_human t =
  match t.result with
  | Proved ->
    Printf.sprintf "PROVED   %s\n         %s" t.property_name t.property_description
  | Vacuous ->
    Printf.sprintf
      "VACUOUS  %s\n         %s\n         The property's forbidden request class is empty; no config was verified."
      t.property_name t.property_description
  | Violated ce ->
    Printf.sprintf "VIOLATED %s\n         %s" t.property_name ce.note
  | Unknown reason ->
    Printf.sprintf "UNKNOWN  %s" reason

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
let schema_version = 4

let counterexample_json ce =
  Printf.sprintf
    "{\"principal\":%s,\"action\":%s,\"path\":%s,\"host\":%s,\"source_ip\":%s,\"route\":%s,\"service\":%s,\"shadowed_route\":%s,\"shadowed_service\":%s}"
    (jstring ce.principal) (jstring ce.action) (jstring ce.path) (jstring ce.host)
    (jstring (Cidr.string_of_ip ce.source_ip))
    (jopt ce.route) (jopt ce.service)
    (jopt ce.shadowed_route) (jopt ce.shadowed_service)

let to_json t =
  let prop = jstring t.property_name in
  let head =
    Printf.sprintf "\"schema_version\":%d,\"property\":%s" schema_version prop
  in
  match t.result with
  | Proved ->
    Printf.sprintf "{\"result\":\"proved\",%s,\"counterexample\":null}" head
  | Vacuous ->
    Printf.sprintf "{\"result\":\"vacuous\",%s,\"counterexample\":null}" head
  | Violated ce ->
    Printf.sprintf "{\"result\":\"violated\",%s,\"counterexample\":%s}" head
      (counterexample_json ce)
  | Unknown reason ->
    Printf.sprintf
      "{\"result\":\"unknown\",%s,\"counterexample\":null,\"reason\":%s}" head
      (jstring reason)
