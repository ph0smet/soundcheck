type t = {
  name           : string;
  description    : string;
  forbidden_when : Ir.condition;
}

let must_deny ~name ~description forbidden_when =
  { name; description; forbidden_when }

let no_anonymous_access ~path_prefix =
  must_deny
    ~name:"no-anonymous-access"
    ~description:
      (Printf.sprintf "No anonymous request may be allowed under %s" path_prefix)
    (Ir.And [ Ir.Path_prefix path_prefix; Ir.Is_anonymous ])
