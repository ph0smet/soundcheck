# YAML scalar fidelity boundary

The October contracts/evaluation batch includes the previously deferred shared
YAML scalar-fidelity assessment. Its bounded change is to reject scalar input
that the installed YAML binding cannot represent faithfully, before either a
Kong configuration or a frozen contract is converted.

## Finding and independent expectation

YAML's `\0`, `\x00`, `\u0000`, and `\U00000000` double-quoted escapes denote the
NUL character. Other styles treat this backslash text literally. These rules are
defined by [YAML 1.2.2 §5.7](https://yaml.org/spec/1.2.2/#57-escaped-characters).

In ocaml-yaml **3.2.0**, `Event.Scalar.value` is bound as a Ctypes `string` in
[`types/bindings/yaml_bindings_types.ml`](https://github.com/avsm/ocaml-yaml/blob/v3.2.0/types/bindings/yaml_bindings_types.ml).
[`lib/stream.ml`](https://github.com/avsm/ocaml-yaml/blob/v3.2.0/lib/stream.ml)
reads that field and ignores libyaml's explicit scalar length. Both the stream
and AST APIs therefore truncate at the decoded NUL. Checking the returned OCaml
string for NUL cannot detect this loss.

A direct C probe against the package's vendored libyaml returned length **12**
for `before<NUL>after` for each of the four escapes, including the suffix. The
baseline Soundcheck reader returned length **6**, `before`, for the same inputs.

For example, `"key-auth\u0000custom"` becomes `key-auth`, and a frozen method
`"GET\u0000POST"` becomes `GET`. This establishes changed input and contract
identity, not a demonstrated false verdict for an accepted live Kong deployment.
Kong's own schema/plugin validation remains separate from Soundcheck's parser.

## Accepted boundary

`Parse.check_yaml_stream` rejects raw NUL characters and NUL-producing escapes
inside double-quoted scalar spans before conversion. It uses libyaml's scalar
style and source positions rather than guessing YAML quoting with a global
search. The position projection follows libyaml's Unicode-character indexing
and initial-BOM handling for UTF-8 and BOM-marked UTF-16LE/BE.

The source bytes are never rewritten. Ordinary escapes, nonzero escaped control
characters, escaped backslashes, Unicode, literal backslash text in plain,
single-quoted and block scalars, and comments remain accepted. Explicit tags,
aliases, duplicate/merge keys, and extra documents retain their existing
fail-closed behavior. No report version, contract identity for accepted inputs,
solver semantics, or Kong assurance profile changes.

## Acceptance evidence

`test/scalar_fidelity_t.ml` checks each NUL spelling in keys and values, nested
ignored fields, escape parity, anchored scalars, comments, line continuations,
Unicode/BOM/UTF-16 positions, raw NUL, and malformed encodings. Expected decoded
strings are literal independent values, not YAML round trips. It also checks
the plugin-name and frozen-method examples above through their actual readers.
Existing parser and contract tests remain required, including the retained
nonzero control-character canonicalization case.

Local focused acceptance covers **92** scalar checks, `parse_t`, and
`contract_spec_t`. Running the new scalar checks against the baseline parser
fails on the first NUL escape, confirming the regression detects the original
loss rather than merely restating the implementation. Integrated regression
and conformance gates remain the responsibility of the combined branch.
Independent review also exercised 4,320 accepted NUL-input combinations with
no bypass. It found a compatibility case with a line-start BOM between an anchor
and scalar; the guard preserves that syntax, with paired allowed/rejected cases
for UTF-8 and UTF-16 encodings.
