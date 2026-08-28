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

(* Admin API reachable, unauthenticated, from outside a trusted address block.

   Reuses the reduced-reachability trick: [reach_via] narrows the allowed-predicate
   to rules whose route proxies the administrative API, so a satisfying model is
   "an anonymous request from an untrusted address that reaches an admin-targeting
   route". The "which routes count" half lives in [reach_via], not in the request
   predicate.

   [Is_anonymous] is in the forbidden class deliberately, and it is what makes the
   property agree with Kong's own guidance rather than overshoot it. Kong's "Secure
   the Admin API" documents TWO sanctioned protections: restrict the network, or
   expose the Admin API through a route carrying an auth plugin. Forbidding every
   untrusted-source request would flag that second pattern — Kong's own
   recommendation — as a violation. Requiring the request to be anonymous exempts
   both protections for free: an ip-restricted route's guard cannot hold for an
   outside address, and an auth-required route's guard cannot hold for an
   anonymous one. What remains flagged is an admin surface with neither. *)
let admin_api_not_reachable ~(trusted : Cidr.t) =
  must_deny
    ~reach_via:(fun (r : Ir.rule) -> r.targets_admin)
    ~name:"admin-api-not-reachable"
    ~description:
      (Printf.sprintf
         "The admin API must not be reachable, unauthenticated, from outside %s"
         (Cidr.to_string trusted))
    (Ir.And [ Ir.Not (Ir.Source_in trusted); Ir.Is_anonymous ])
