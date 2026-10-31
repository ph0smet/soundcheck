open Soundcheck_core
open Soundcheck_kong

(* Independent bound obligations, based on pinned Kong 3.9.3:
   ip-restriction checks deny before a nonempty allow list, and rate-limiting
   can reject a request when its runtime counter reaches the configured limit.
   This is not live IPv6, quota, datastore, or commercial-plugin coverage. *)
let checked = ref 0
let check label predicate =
  incr checked;
  if not predicate then failwith label

let get = function Ok value -> value | Error error -> failwith error
let block = get (Cidr.parse "10.0.0.0/8")

let config plugins =
  "_format_version: '3.0'\nservices: [{name: api, url: 'http://upstream:8000', "
  ^ "routes: [{name: guarded, paths: [/admin], methods: [GET], plugins: "
  ^ plugins ^ "}]}]"

let policy source = get (Parse.parse_string source) |> Lower.to_policy

let request address : Ir.request =
  { principal = Authenticated "fixture"; action = "GET"; resource = "/admin";
    context = []; source = (get (Cidr.parse address)).base; host = "example.test";
    scheme = "http"; sni = "" }

let inside = request "10.2.3.4"
let outside = request "192.0.2.4"

let bounds label policy request ~may ~must =
  check (label ^ ": possible allowance") (Ir.possibly_allows policy request = may);
  check (label ^ ": definite allowance") (Ir.definitely_allows policy request = must)

let refine policy request actual =
  (not (Ir.definitely_allows policy request) || actual)
  && (not actual || Ir.possibly_allows policy request)

let mutate_guard f (policy : Ir.policy) =
  { policy with rules = List.map f policy.rules }

let paired = Verify.Authenticated_access
  { path_prefix = "/admin"; method_ = Some "GET"; host = None }

let () =
  let known = policy (config
      "[{name: ip-restriction, config: {allow: [10.0.0.0/8]}}]") in
  bounds "known allow: inside" known inside ~may:true ~must:true;
  bounds "known allow: outside" known outside ~may:false ~must:false;

  (* IPv6 is valid target syntax but outside this connector's IPv4 model.
     Its abstract membership is unknown, not the empty set. In an allow list,
     keeping only the understood IPv4 entry would silently narrow may-allow. *)
  let mixed_allow = policy (config
      "[{name: ip-restriction, config: {allow: [10.0.0.0/8, '2001:db8::/32']}}]") in
  bounds "mixed allow: inside" mixed_allow inside ~may:true ~must:false;
  bounds "mixed allow: outside" mixed_allow outside ~may:true ~must:false;
  let mixed_deny = policy (config
      "[{name: ip-restriction, config: {deny: [10.0.0.0/8, '2001:db8::/32']}}]") in
  bounds "mixed deny: known denial" mixed_deny inside ~may:false ~must:false;
  bounds "mixed deny: outside" mixed_deny outside ~may:true ~must:false;
  let mixed_both = policy (config
      "[{name: ip-restriction, config: {allow: [10.0.0.0/8, '2001:db8::/32'], deny: [192.0.2.0/24]}}]") in
  bounds "mixed allow retains known deny" mixed_both outside ~may:false ~must:false;
  bounds "mixed allow retains uncertainty" mixed_both inside ~may:true ~must:false;

  (* Enumerate independently authored completions of the unknown membership.
     This checks the abstraction's promised bounds, not actual IPv6 execution. *)
  List.iter (fun request ->
    List.iter (fun unknown_matches ->
      let known_matches = Cidr.contains block request.Ir.source in
      check "mixed allow bounds over membership completions"
        (refine mixed_allow request (known_matches || unknown_matches));
      check "mixed deny bounds over membership completions"
        (refine mixed_deny request (not (known_matches || unknown_matches))))
      [ false; true ]) [ inside; outside ];

  let narrowed = mutate_guard
      (fun (rule : Ir.rule) ->
        { rule with guard = Ir.And [ rule.guard; Ir.Source_in block ] }) mixed_allow in
  check "mixed-allow-narrowing mutation must fail the independent upper bound"
    (not (refine narrowed outside true));
  let exact_unknown = mutate_guard
      (fun (rule : Ir.rule) -> { rule with guard_complete = true }) mixed_deny in
  check "unknown-cidr-completeness mutation must fail the independent lower bound"
    (not (refine exact_unknown outside false));

  let ordinary = config "[{name: key-auth}]" in
  check "control without runtime quota proves functionality"
    ((get (Verify.run ~property:paired ordinary)).Report.result = Proved);
  (* Recognized plugin names have the same conservative runtime dependency.
     Only OSS rate-limiting's quota branch is independently sourced here;
     this does not claim execution of Enterprise or response/GraphQL plugins. *)
  List.iter (fun plugin ->
    let source = config (Printf.sprintf
        "[{name: key-auth}, {name: %s, config: {minute: 1}}]" plugin) in
    let lowered = policy source in
    bounds (plugin ^ ": authenticated request") lowered inside ~may:true ~must:false;
    bounds (plugin ^ ": anonymous request") lowered
      { inside with principal = Anonymous } ~may:false ~must:false;
    List.iter (fun quota_allows ->
      check (plugin ^ ": runtime quota completion bounds")
        (refine lowered inside quota_allows)) [ false; true ];
    let exact_quota = mutate_guard
        (fun (rule : Ir.rule) -> { rule with guard_complete = true }) lowered in
    check "quota-definite-allow mutation must fail the exhausted-quota lower bound"
      (not (refine exact_quota inside false));
    let report = get (Verify.run ~property:paired source) in
    (match report.result, report.clause, report.assurance with
     | Violated _, Some { kind = Must_allow; name = "authenticated-access-allowed"; _ },
       Some { status = Conservative; _ } -> incr checked
     | _ -> failwith (plugin ^ ": runtime dependency must not prove paired functionality")))
    [ "rate-limiting"; "rate-limiting-advanced";
      "response-ratelimiting"; "graphql-rate-limiting-advanced" ];
  Printf.printf "Plugin bound checks passed (%d checks, 3 mutation shapes).\n" !checked
