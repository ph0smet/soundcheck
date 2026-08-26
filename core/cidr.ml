(* IPv4 address blocks, as used by source-address policy.

   A CIDR block is a bitmask test, which is why the symbolic source address is a
   32-bit bitvector rather than a string: membership becomes [(= (bvand ip mask)
   base)], which SMT solvers decide cheaply and exactly. Encoding addresses as
   strings would have made every range test a string-arithmetic problem for no
   gain.

   IPv6 is out of scope for v0 and is REJECTED by {!parse} rather than ignored, so
   a config using it cannot be silently mis-modelled. *)

type t = {
  base : int32;  (** network address, already masked *)
  bits : int;    (** prefix length, 0..32 *)
}

let mask_of_bits bits =
  if bits = 0 then 0l
  else Int32.shift_left (-1l) (32 - bits)

let of_octets a b c d =
  Int32.logor
    (Int32.shift_left (Int32.of_int a) 24)
    (Int32.logor
       (Int32.shift_left (Int32.of_int b) 16)
       (Int32.logor (Int32.shift_left (Int32.of_int c) 8) (Int32.of_int d)))

let parse (s : string) : (t, string) result =
  let s = String.trim s in
  if String.contains s ':' then
    Error (Printf.sprintf "IPv6 address %S is not modelled" s)
  else
    let addr, bits_str =
      match String.index_opt s '/' with
      | None -> (s, None)
      | Some i ->
        (String.sub s 0 i, Some (String.sub s (i + 1) (String.length s - i - 1)))
    in
    let octets =
      match String.split_on_char '.' addr with
      | [ a; b; c; d ] ->
        (match
           (int_of_string_opt a, int_of_string_opt b, int_of_string_opt c,
            int_of_string_opt d)
         with
         | Some a, Some b, Some c, Some d
           when List.for_all (fun o -> o >= 0 && o <= 255) [ a; b; c; d ] ->
           Some (a, b, c, d)
         | _ -> None)
      | _ -> None
    in
    let bits =
      match bits_str with
      | None -> Ok 32 (* a bare address is a single host *)
      | Some b -> (
        match int_of_string_opt (String.trim b) with
        | Some n when n >= 0 && n <= 32 -> Ok n
        | Some n -> Error (Printf.sprintf "prefix /%d out of range in %S" n s)
        | None -> Error (Printf.sprintf "bad prefix in %S" s))
    in
    match (octets, bits) with
    | None, _ -> Error (Printf.sprintf "bad IPv4 address %S" s)
    | _, Error e -> Error e
    | Some (a, b, c, d), Ok bits ->
      let raw = of_octets a b c d in
      Ok { base = Int32.logand raw (mask_of_bits bits); bits }

let contains (c : t) (ip : int32) : bool =
  Int32.logand ip (mask_of_bits c.bits) = c.base

let to_string (c : t) =
  let b i = Int32.to_int (Int32.logand (Int32.shift_right_logical c.base i) 0xFFl) in
  Printf.sprintf "%d.%d.%d.%d/%d" (b 24) (b 16) (b 8) (b 0) c.bits

let string_of_ip (ip : int32) =
  let b i = Int32.to_int (Int32.logand (Int32.shift_right_logical ip i) 0xFFl) in
  Printf.sprintf "%d.%d.%d.%d" (b 24) (b 16) (b 8) (b 0)

let hex32 (v : int32) = Printf.sprintf "#x%08lx" (Int32.logand v 0xFFFFFFFFl)

let to_smt ~(var : string) (c : t) : string =
  if c.bits = 0 then "true" (* 0.0.0.0/0 matches every address *)
  else
    Printf.sprintf "(= (bvand %s %s) %s)" var
      (hex32 (mask_of_bits c.bits))
      (hex32 c.base)
