(** Fail-closed regex-path boundary shared by the supported Kong 3.9.3
    [traditional] and [traditional_compatible] router flavors. *)

val parse : string -> (Soundcheck_core.Regex.parsed, string) result
(** Parse a regex path after removing Kong's leading [~]. The accepted pattern
    atoms are ASCII literals, positive ASCII classes, ordinary/control/one-byte
    hex escapes, grouping (including distinct nonreserved named captures),
    grouped alternation, and greedy/lazy repetition within {!Soundcheck_core.Regex}
    parser limits. A redundant leading [^] is accepted. Additional conservative
    connector limits are 2048 source bytes, 32 nested groups, numeric repetition
    bounds at most 64, and [Regex.syntax.expansion_cost] at most
    512. This keeps accepted syntax well below Rust's default AST nesting limit
    of 250 and refuses large repeat expansions rather than claiming support
    merely because their counts fit in a machine integer.

    This is a restriction on pattern atoms, NOT an ASCII-only request domain:
    an unanchored pattern may still match a prefix of a path with any UTF-8
    suffix. Callers append [Star Any] as before.

    Rejects end anchors, dot, negated classes, all shorthand classes, non-ASCII
    pattern atoms, the reserved capture name [uri_postfix], and literal/class
    occurrences of [?<] rewritten by the compatible router. Both target engines
    must agree without assuming ASCII requests or silently choosing a flavor.
    Other malformed/unsupported syntax is rejected by the core parser. Limits
    here are conservative input boundaries, not a model of target runtime or
    compilation resource limits. *)
