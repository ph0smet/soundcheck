(** A small regular-expression AST with a parser, an SMT-LIB2 translation, and a
    concrete matcher.

    The AST exists so that the symbolic side ({!to_smt}) and the concrete side
    ({!matches_full}) interpret exactly the same language. Handing patterns to a
    PCRE library on one side and SMT-LIB regexes on the other would make every
    corner of PCRE semantics a place the two could silently disagree — and a
    disagreement here is a wrong verdict.

    {!parse} accepts only the plainly-regular subset and REJECTS the rest with a
    reason, rather than approximating it: backreferences are not regular at all,
    while possessive quantifiers and atomic groups change the accepted language
    ([a*+a] never matches ["aa"]) and so cannot be read as greedy. Lazy
    quantifiers are accepted and treated as greedy, since they change which match
    is found but never whether one exists. *)

type t =
  | Empty                                (** matches only the empty string *)
  | Any                                  (** [.] *)
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
      (** the pattern ended with [$]. Whether the pattern must also cover the rest
          of the subject is the caller's decision — for Kong it does not, so the
          connector appends [Star Any] when this is [false]. *)
}

val parse : string -> (parsed, string) result
(** Parse the supported subset. [Error reason] names the construct that is out of
    scope, phrased for a config author. A leading [^] is accepted and dropped (the
    caller anchors the start already); a trailing [$] sets {!anchored_end}. *)

val to_smt : t -> string
(** SMT-LIB2 regular expression (sort [RegLan]), for use under [str.in_re]. *)

val smt_string : string -> string
(** A string as an SMT-LIB2 literal, quotes doubled. Exposed so callers emitting
    [str.in_re] alongside a subject escape it exactly as {!to_smt} does. *)

val matches_full : t -> string -> bool
(** Concrete membership: does the {b whole} string belong to the language?
    Deliberately the same semantics {!to_smt} encodes, so a counterexample can be
    re-checked without a second regex engine. *)
