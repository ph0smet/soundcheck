type t = {
  name           : string;
  description    : string;
  forbidden_when : Ir.condition;
  reach_via      : Ir.rule -> bool;
}

let must_deny ?(reach_via = fun _ -> true) ~name ~description forbidden_when =
  { name; description; forbidden_when; reach_via }

let no_anonymous_access ~path_prefix =
  must_deny
    ~name:"no-anonymous-access"
    ~description:
      (Printf.sprintf "No anonymous request may be allowed under %s" path_prefix)
    (Ir.And [ Ir.Path_prefix path_prefix; Ir.Is_anonymous ])

let rate_limit_on_public =
  must_deny
    ~name:"rate-limit-on-public"
    ~description:"Every anonymous-reachable route must have a rate-limiting plugin"
    ~reach_via:(fun (r : Ir.rule) -> not r.rate_limited)
    Ir.Is_anonymous

(* Admin API reachable from outside a trusted address block.

   Reuses the reduced-reachability trick: [reach_via] narrows the allowed-predicate
   to rules whose route proxies the administrative API, so a satisfying model is
   "a request from an untrusted address that reaches an admin-targeting route".
   The forbidden class is therefore just "source outside [trusted]" — the "which
   routes count" half lives in [reach_via], not in the request predicate.

   A route that already restricts source addresses is exempt for free: its guard
   cannot hold for an address outside what it permits, exactly as auth-required
   routes fall out of rate-limit-on-public. *)
let admin_api_not_reachable ~(trusted : Cidr.t) =
  must_deny
    ~reach_via:(fun (r : Ir.rule) -> r.targets_admin)
    ~name:"admin-api-not-reachable"
    ~description:
      (Printf.sprintf
         "The admin API must not be reachable from outside %s"
         (Cidr.to_string trusted))
    (Ir.Not (Ir.Source_in trusted))
