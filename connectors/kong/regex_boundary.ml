open Soundcheck_core

(* Independent target basis (Kong 3.9.3, a643428bc4d5397152164a63bcc0f8bc65fce69d):
   - kong/router/traditional.lua uses ngx.re.match(..., "ajo"), i.e. PCRE2 10.44
     anchored byte matching, without UTF/UCP/DOTALL/DOLLAR_ENDONLY options.
   - kong/router/transform.lua prepends ^ WITHOUT grouping and globally rewrites
     ?< to ?P<. ATC ffd11db657115769bf94f0c4f915f98300bc26b6 uses regex::Regex,
     not regex::bytes::Regex, with Unicode enabled; Kong pins regex 1.11.1.
   - PCRE's $ accepts a position before final LF, Rust's default $ does not.
     Dot/negative classes consume bytes in one engine, Unicode scalars in the
     other; shorthand classes also differ in membership. Raw non-ASCII atoms
     can differ under repetition even when the complete literal would agree.

   Primary sources:
   https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/router/transform.lua
   https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/router/traditional.lua
   https://github.com/Kong/atc-router/blob/ffd11db657115769bf94f0c4f915f98300bc26b6/src/parser.rs
   https://github.com/PCRE2Project/pcre2/blob/pcre2-10.44/doc/pcre2pattern.3
   https://docs.rs/regex/1.11.1/regex/#unicode

   Do not replace this boundary with an implicit ASCII request assumption. *)

let angle_opening_occurrences pattern =
  let count = ref 0 in
  for i = 0 to String.length pattern - 2 do
    if pattern.[i] = '?' && pattern.[i + 1] = '<' then incr count
  done;
  !count

let non_ascii c = Char.code c > 127

let rec unsupported_atoms = function
  | Regex.Any | Regex.Class (true, _) ->
    Some "dot wildcards and negated classes have unmodeled byte/Unicode semantics across Kong router flavors"
  | Regex.Lit s when String.exists non_ascii s ->
    Some "non-ASCII regex atoms have unmodeled byte/Unicode semantics across Kong router flavors"
  | Regex.Class (false, ranges)
    when List.exists (fun (lo, hi) -> non_ascii lo || non_ascii hi) ranges ->
    Some "non-ASCII regex class ranges have unmodeled byte/Unicode semantics across Kong router flavors"
  | Regex.Repeat (_, lo, hi)
    when lo > 64 || Option.fold ~none:false ~some:(fun upper -> upper > 64) hi ->
    Some "numeric regex repetition exceeds the common-language limit of 64"
  | Regex.Concat patterns | Regex.Alt patterns -> List.find_map unsupported_atoms patterns
  | Regex.Star pattern | Regex.Plus pattern | Regex.Opt pattern
  | Regex.Repeat (pattern, _, _) -> unsupported_atoms pattern
  | Regex.Empty | Regex.Lit _ | Regex.Class (false, _) -> None

let parse pattern =
  if String.length pattern > 2048 then
    Error "regex source exceeds the common-language limit of 2048 bytes"
  else
  match Regex.parse_with_syntax pattern with
  | Error _ as error -> error
  | Ok (parsed, syntax) ->
    (* Rust's default AST limit is 250, not 250 groups. With no nested classes
       and at most one concat/alt/quantifier per group level, depth 32 bounds
       the syntactic path by 4*32+8 nodes, allowing root/leaf class structure and
       the added start anchor (still comfortably below 250).
       The cost bound also counts erased group/name data inside repetitions,
       rejecting large expansions before either engine's compile limits matter.
       These intentionally small support limits do not model match-time limits. *)
    if syntax.max_group_depth > 32 then
      Error "regex group nesting exceeds the common-language limit of 32"
    else if syntax.expansion_cost > 512 then
      Error "regex expansion exceeds the common-language cost limit of 512"
    else if parsed.anchored_end then
      Error "trailing $ has different final-newline semantics across Kong router flavors"
    else if syntax.shorthand_classes <> [] then
      Error "regex shorthand classes have different Unicode membership across Kong router flavors; use explicit ASCII positive classes"
    else if List.mem "uri_postfix" syntax.named_captures then
      Error "capture name uri_postfix is reserved by Kong's traditional router"
    else if angle_opening_occurrences pattern <> syntax.angle_named_captures then
      Error "literal ?< is rewritten by Kong's traditional_compatible router"
    else match unsupported_atoms parsed.re with
      | Some reason -> Error reason
      | None -> Ok parsed
