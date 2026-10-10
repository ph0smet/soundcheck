(** A small regular-expression AST with a parser, an SMT-LIB2 translation, and a
    concrete matcher.

    The AST exists so that the symbolic side ({!to_smt}) and the concrete side
    ({!matches_full}) interpret exactly the same language. Handing patterns to a
    PCRE library on one side and SMT-LIB regexes on the other would make every
    corner of PCRE semantics a place the two could silently disagree — and a
    disagreement here is a wrong verdict.

    The AST and parser are byte-oriented, not Unicode-scalar regular expressions.
    Connectors must impose their target's compatibility boundary separately.
    {!parse} accepts a bounded regular subset and REJECTS the rest with a
    reason, rather than approximating it: backreferences are not regular at all,
    while possessive quantifiers and atomic groups change the accepted language
    ([a*+a] never matches ["aa"]) and so cannot be read as greedy. Lazy
    quantifiers are accepted and treated as greedy, since they change which match
    is found but never whether one exists. *)

type t =
  | Empty                                (** matches only the empty string *)
  | Any                                  (** any byte, including newline *)
  | Lit of string
  | Class of bool * (char * char) list   (** negated?, inclusive ranges *)
  | Concat of t list
  | Alt of t list
  | Star of t
  | Plus of t
  | Opt of t
  | Repeat of t * int * int option       (** [{n}], [{n,}], [{n,m}] *)

type parsed = {
  re           : t;
  anchored_end : bool;
      (** the pattern ended with an unescaped [$]. This is syntax metadata, not
          a claim that every target's end anchor means strict end-of-string. *)
}

type syntax = {
  shorthand_classes : char list;
      (** Shorthand letters [dDwWsS], in source order (including repetitions).
          A shorthand's origin is otherwise lost when lowered to a class. *)
  named_captures : string list;
      (** Validated, distinct ASCII capture names in source order. *)
  angle_named_captures : int;
      (** Number of genuine [(?<name>...)] openers, excluding [(?P<name>...)].
          Useful when a target textually rewrites that opening syntax. *)
  max_group_depth : int;
      (** Maximum simultaneously open groups, before groups are erased. *)
  expansion_cost : int;
      (** Saturating abstract syntax cost, NOT target compiled bytes: literal
          byte count (minimum one), one plus two per class range, one per
          concatenation/alternative/quantifier/group plus children, and capture
          name bytes. Numeric repeats multiply their child's entire cost,
          including groups, by [max 1 hi] or [lo + 1] for an unbounded repeat.
          Costs saturate at [max_int]. *)
}

val parse : string -> (parsed, string) result
(** Parse the byte-oriented subset. [Error reason] names an invalid or unsupported
    construct. Supported: literals; dot excluding LF; ordinary positive/negative
    classes; ASCII [\d], [\w], [\s] (the latter includes VT) and their complements;
    escaped ASCII punctuation or space except [\<] and [\>]; [\a\f\n\r\t]; one-byte
    [\xHH] or [\x{H}]/[\x{HH}]; ordinary/noncapturing/named groups; grouped
    alternation; greedy/lazy [?*+] and [{n}], [{n,}], [{n,m}].

    Repetition counts may not exceed 65535; group nesting may not exceed 250;
    names are distinct ASCII identifiers of 1 to 128 characters. These are
    explicit parser limits, not a guarantee about another engine's resources.
    Unknown escapes, POSIX/nested/set-operation classes, nonliteral range
    endpoints, malformed or stacked quantifiers, and top-level alternation fail
    closed. Parenthesize alternation explicitly. A leading [^] is dropped (the
    caller anchors the start); a trailing unescaped [$] sets {!anchored_end}.
    All other assertions, backreferences, lookaround, inline flags, atomic groups,
    and possessive quantifiers are unsupported. [Any] is unchanged by dot parsing:
    unlike a parsed dot, it includes newline and remains useful for suffixes. *)

val parse_with_syntax : string -> (parsed * syntax, string) result
(** Like {!parse}, retaining syntax facts needed by target-specific boundaries. *)

val to_smt : t -> string
(** SMT-LIB2 regular expression (sort [RegLan]), for use under [str.in_re]. *)

val smt_string : string -> string
(** A byte-oriented string as an ASCII SMT-LIB2 literal. Quotes are doubled;
    backslashes and nonprintable bytes use Unicode escapes. Exposed so callers
    emitting [str.in_re] alongside a subject escape it exactly as {!to_smt} does. *)

val matches_full : t -> string -> bool
(** Concrete membership: does the {b whole} string belong to the language?
    Deliberately the same semantics {!to_smt} encodes, so a counterexample can be
    re-checked without a second regex engine. *)
