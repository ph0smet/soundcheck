(* End-to-end smoke test: same property, two policies.
   - insecure: an /admin route with no auth  -> anonymous access ALLOWED -> VIOLATED
   - secure:   an /admin route requiring auth -> anonymous access DENIED  -> PROVED
   Demonstrates the full pipeline: IR -> SMT-LIB2 -> z3 CLI -> result. *)

open Soundcheck_core

let run label (policy : Ir.policy) (prop : Property.t) =
  let smt = Smt_encode.to_smtlib policy prop in
  let result = Solve.check smt in
  Printf.printf "[%-16s] %s\n" label (Solve.string_of_result result)

let () =
  let insecure : Ir.policy =
    { rules =
        [ Ir.{ id = "admin-route"; when_ = Path_prefix "/admin";
               decision = Allow; rate_limited = false } ];
      default = Ir.Deny }
  in
  let secure : Ir.policy =
    { rules =
        [ Ir.{ id = "admin-route";
               when_ = And [ Path_prefix "/admin"; Requires_auth ];
               decision = Allow; rate_limited = false } ];
      default = Ir.Deny }
  in
  let prop = Property.no_anonymous_access ~path_prefix:"/admin" in
  run "insecure config" insecure prop;
  run "secure config" secure prop
