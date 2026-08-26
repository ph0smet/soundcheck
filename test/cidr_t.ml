(* Unit tests for CIDR parsing and membership. Pure logic with fiddly edges
   (masking, bare addresses, out-of-range prefixes), and it underpins the
   source-address dimension, so it is checked directly rather than only through
   end-to-end cases. *)

open Soundcheck_core

let failures = ref 0

let check name cond =
  if cond then Printf.printf "[ok]    %s\n" name
  else begin
    incr failures;
    Printf.printf "[FAIL]  %s\n" name
  end

let parses s = match Cidr.parse s with Ok c -> Some c | Error _ -> None

let contains block ip =
  match (Cidr.parse block, Cidr.parse ip) with
  | Ok b, Ok i -> Cidr.contains b i.Cidr.base
  | _ -> false

let () =
  (* round-trip: the base is masked on parse, so host bits are discarded *)
  check "10.0.0.0/8 round-trips"
    (match parses "10.0.0.0/8" with
     | Some c -> Cidr.to_string c = "10.0.0.0/8"
     | None -> false);
  check "host bits masked off: 10.1.2.3/8 -> 10.0.0.0/8"
    (match parses "10.1.2.3/8" with
     | Some c -> Cidr.to_string c = "10.0.0.0/8"
     | None -> false);
  check "bare address is /32"
    (match parses "1.2.3.4" with
     | Some c -> Cidr.to_string c = "1.2.3.4/32"
     | None -> false);
  check "0.0.0.0/0 encodes as true"
    (match parses "0.0.0.0/0" with
     | Some c -> Cidr.to_smt ~var:"ip" c = "true"
     | None -> false);

  (* rejections must be loud, not silently mis-parsed *)
  check "IPv6 rejected" (parses "::1" = None);
  check "IPv6 with prefix rejected" (parses "2001:db8::/32" = None);
  check "prefix > 32 rejected" (parses "10.0.0.0/33" = None);
  check "negative prefix rejected" (parses "10.0.0.0/-1" = None);
  check "octet > 255 rejected" (parses "10.0.0.256" = None);
  check "too few octets rejected" (parses "10.0.0" = None);
  check "garbage rejected" (parses "junk" = None);

  (* membership *)
  check "10.0.0.0/8 contains 10.5.6.7" (contains "10.0.0.0/8" "10.5.6.7");
  check "10.0.0.0/8 excludes 11.5.6.7" (not (contains "10.0.0.0/8" "11.5.6.7"));
  check "/24 contains its range" (contains "192.168.1.0/24" "192.168.1.99");
  check "/24 excludes the next block"
    (not (contains "192.168.1.0/24" "192.168.2.1"));
  check "/32 is exact" (contains "1.2.3.4" "1.2.3.4");
  check "/32 excludes a neighbour" (not (contains "1.2.3.4" "1.2.3.5"));
  check "/0 contains everything" (contains "0.0.0.0/0" "203.0.113.9");
  (* the high bit is where a signed-int32 mistake would show up *)
  check "high-bit address handled" (contains "240.0.0.0/4" "255.255.255.255");
  check "high-bit block excludes low address"
    (not (contains "240.0.0.0/4" "10.0.0.1"));

  if !failures > 0 then (
    Printf.printf "\n%d failure(s)\n" !failures;
    exit 1)
  else print_endline "\nall cidr checks passed"
