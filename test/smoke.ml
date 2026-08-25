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
  (* The two policies differ ONLY in [guard]: same routing, different policy on
     the route that serves it. That separation is the point of the IR split. *)
  let admin_prefix = "/admin" in
  let route ~guard : Ir.rule =
    Ir.{ id = "admin-route";
         match_ = Path_prefix admin_prefix;
         guard;
         priority = { Ir.shape = 0; tier = 0; rank = String.length admin_prefix };
         decision = Allow;
         rate_limited = false }
  in
  let insecure : Ir.policy =
    { rules = [ route ~guard:Ir.True ]; default = Ir.Deny }
  in
  let secure : Ir.policy =
    { rules = [ route ~guard:Ir.Requires_auth ]; default = Ir.Deny }
  in
  let prop = Property.no_anonymous_access ~path_prefix:"/admin" in
  run "insecure config" insecure prop;
  run "secure config" secure prop
