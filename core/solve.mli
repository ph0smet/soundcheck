(** Run an SMT-LIB2 query through the [z3] CLI and interpret the outcome. *)

type model = {
  path    : string;
  method_ : string;
  is_anon : bool;
  src_ip  : int32;   (** IPv4 source address of the violating request *)
  host    : string;  (** request Host of the violating request *)
  scheme  : string;  (** normalized request scheme *)
  sni     : string;  (** TLS server name, or empty when absent *)
  headers : (string * string) list;
      (** Lowercase header-name/value memberships required by the model. *)
}
(** A concrete counterexample request extracted from a [sat] model. *)

type result =
  | Proved                 (** [unsat]: no request violates the property *)
  | Violated of model      (** [sat]: a concrete violating request *)
  | Unknown of string      (** Unknown, failed/timed-out process, or invalid reply. *)

val check : ?z3:string -> ?timeout:float -> ?emit_smt:string -> string -> result
(** [check ?z3 ?timeout ?emit_smt smtlib] runs a single query through
    [z3 -smt2] (default binary ["z3"], resolved on PATH). The script must
    end in one [check-sat], optionally followed only by [get-value] for named
    request fields. First a temporary script without that observation is run.
    After SAT, a second invocation replays the full script and must again
    return SAT with values. Unexpected responses,
    nonzero exit, stderr diagnostics, or malformed/missing values fail closed.

    [timeout] is a finite positive wall-clock duration in seconds (default 10),
    shared across both invocations, including output and process exit. Timeout
    cleanup allows at most another 0.5 seconds. Captured output is limited to
    4 MiB per stream per invocation. Only the directly launched solver PID is
    supervised; arbitrary detached descendants of wrappers are not managed.

    When [emit_smt] is [Some path] the query is written there and kept, so the
    complete planned obligation remains inspectable. This is the original query,
    not a subprocess transcript: direct batch replay after UNSAT can report a
    model-unavailable error for the conditional [get-value] after the verdict.
    The assertions are unchanged. Temporary execution files are removed. *)

val version : ?z3:string -> ?timeout:float -> unit -> (string, string) Stdlib.result
(** Capture [z3 -version] for evidence provenance. Failure is explicit rather
    than inventing a solver version. The same timeout and capture bounds apply. *)

val string_of_result : result -> string
