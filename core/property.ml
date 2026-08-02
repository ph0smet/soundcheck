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
