(lang dune 3.11)
(name soundcheck)

(generate_opam_files true)

(license MIT)
(authors "Sourav Kumar")
(maintainers "Sourav Kumar")
(source
 (github ph0smet/soundcheck))

(package
 (name soundcheck)
 (synopsis "Proof-or-counterexample verification for declarative security policy")
 (description
  "Soundcheck proves security invariants over declarative policy artifacts such as API-gateway configurations, returning either a machine-checkable proof that no violating request exists or a concrete counterexample expressed in the config's own vocabulary. Policy is lowered to a shared decision IR, encoded to SMT-LIB2 alongside the negated property, and discharged with Z3.")
 (depends
  (ocaml
   (>= 5.0))
  dune
  yaml))
