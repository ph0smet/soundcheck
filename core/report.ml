(* Presentation of a verification result. Both serializers live here so every
   adapter renders identically — see report.mli. *)

type counterexample = {
  principal : string;
  action    : string;
  path      : string;
  route     : string option;
  service   : string option;
  note      : string;
}

type outcome =
  | Proved
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

let counterexample_json ce =
  Printf.sprintf
    "{\"principal\":%s,\"action\":%s,\"path\":%s,\"route\":%s,\"service\":%s}"
    (jstring ce.principal) (jstring ce.action) (jstring ce.path)
    (jopt ce.route) (jopt ce.service)

let to_json t =
  let prop = jstring t.property_name in
  match t.result with
  | Proved ->
    Printf.sprintf
      "{\"result\":\"proved\",\"property\":%s,\"counterexample\":null}" prop
  | Violated ce ->
    Printf.sprintf
      "{\"result\":\"violated\",\"property\":%s,\"counterexample\":%s}"
      prop (counterexample_json ce)
  | Unknown reason ->
    Printf.sprintf
      "{\"result\":\"unknown\",\"property\":%s,\"counterexample\":null,\"reason\":%s}"
      prop (jstring reason)
