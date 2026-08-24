(* Differential test: the concrete matcher and the SMT translation must agree.

   {!Regex.matches_full} and {!Regex.to_smt} are two independent readings of the
   same AST, and the verifier relies on both — the encoder to search for
   counterexamples, the matcher to confirm a counterexample is genuine. If they
   disagree the corpus validation either rejects a real finding or blesses a
   spurious one, so their agreement is a correctness property in its own right and
   is checked here rather than assumed.

   For every (pattern, subject) pair we compute the matcher's answer and ask z3
   [(str.in_re "subject" <translated>)], and fail on any disagreement. *)

open Soundcheck_core

let z3_says (re : Regex.t) (subject : string) : bool =
  let file = Filename.temp_file "regex_agree" ".smt2" in
  let oc = open_out file in
  Printf.fprintf oc "(set-logic ALL)\n(assert (str.in_re %s %s))\n(check-sat)\n"
    (Regex.smt_string subject) (Regex.to_smt re);
  close_out oc;
  let ic = Unix.open_process_in (Printf.sprintf "z3 -smt2 %s" (Filename.quote file)) in
  let out = In_channel.input_all ic in
  ignore (Unix.close_process_in ic);
  (try Sys.remove file with _ -> ());
  let out = String.trim out in
  if out = "sat" then true
  else if out = "unsat" then false
  else failwith (Printf.sprintf "z3 said %S for %S" out subject)

(* Subjects are ASCII: the matcher works on bytes and SMT-LIB strings are
   sequences of code points, so they coincide only there. Kong paths are
   percent-encoded ASCII in practice. *)
let cases =
  [ ("/admin", [ "/admin"; "/admi"; "/adminx"; "" ]);
    ("/admin/[0-9]+", [ "/admin/1"; "/admin/123"; "/admin/"; "/admin/x"; "/admin/12x" ]);
    ("/admin/\\d+", [ "/admin/7"; "/admin/70"; "/admin/x" ]);
    ("/a.c", [ "/abc"; "/a/c"; "/ac"; "/abbc" ]);
    ("/(foo|bar)/x", [ "/foo/x"; "/bar/x"; "/baz/x"; "/foo/y" ]);
    ("/a*b", [ "b"; "ab"; "aaab"; "/ab"; "ba" ]);
    ("/x/[^/]+", [ "/x/abc"; "/x/a/b"; "/x/"; "/x/a" ]);
    ("/v[0-9]{2}", [ "/v12"; "/v1"; "/v123" ]);
    ("/v[0-9]{2,}", [ "/v12"; "/v1"; "/v1234" ]);
    ("/v[0-9]{1,3}", [ "/v1"; "/v123"; "/v1234"; "/v" ]);
    ("/opt/x?y", [ "/opt/xy"; "/opt/y"; "/opt/xxy" ]);
    ("/lazy/.*?z", [ "/lazy/z"; "/lazy/aaz"; "/lazy/a" ]);
    ("/w/\\w+", [ "/w/abc_1"; "/w/-"; "/w/A9" ]);
    ("/nd/\\D+", [ "/nd/abc"; "/nd/1"; "/nd/a1" ]);
    ("/g/(?:ab)+", [ "/g/ab"; "/g/abab"; "/g/aba"; "/g/" ]);
    ("/n/(?<ver>v[0-9])/x", [ "/n/v1/x"; "/n/vv/x" ]);
    ("/esc/a\\.b", [ "/esc/a.b"; "/esc/axb" ]);
    ("/cls/[a-c-]", [ "/cls/a"; "/cls/-"; "/cls/d" ]);
    ("/alt/(a|b|c)d", [ "/alt/ad"; "/alt/cd"; "/alt/dd" ]);
    ("/nest/((a|b)c)+", [ "/nest/ac"; "/nest/bcac"; "/nest/abc" ]) ]

(* Constructs that must be refused rather than approximated. *)
let must_reject =
  [ ("/(a+)\\1", "backreference");
    ("/a*+b", "possessive quantifier");
    ("/(?>ab)c", "atomic group");
    ("/a(?=b)c", "lookahead");
    ("/a(?<=b)c", "lookbehind");
    ("/a(?!b)c", "negative lookahead");
    ("/a\\bc", "word-boundary assertion");
    ("/unbalanced(", "unbalanced paren");
    ("/[unterminated", "unterminated class") ]

(* Anchoring is a fact about the pattern, not the language, so it is asserted
   directly. Kong leaves the END of a regex path unanchored unless the author
   writes [$]; a leading [^] is redundant because Kong anchors the start anyway. *)
let anchor_cases =
  [ ("/admin/\\d+", false); ("/admin/\\d+$", true); ("^/admin/\\d+", false);
    ("^/admin/\\d+$", true); ("/lit\\$", false) ]

let () =
  let failures = ref 0 in
  List.iter
    (fun (pattern, expected) ->
      match Regex.parse pattern with
      | Error why ->
        incr failures;
        Printf.printf "[FAIL]  %-24s should parse, got: %s\n" pattern why
      | Ok { anchored_end; _ } ->
        if anchored_end <> expected then begin
          incr failures;
          Printf.printf "[FAIL]  %-24s anchored_end=%b expected %b\n" pattern
            anchored_end expected
        end
        else Printf.printf "[ok]    %-24s anchored_end=%b\n" pattern anchored_end)
    anchor_cases;
  List.iter
    (fun (pattern, subjects) ->
      match Regex.parse pattern with
      | Error why ->
        incr failures;
        Printf.printf "[FAIL]  %-24s should parse, got: %s\n" pattern why
      | Ok { re; _ } ->
        List.iter
          (fun subject ->
            let mine = Regex.matches_full re subject in
            let z3 = z3_says re subject in
            if mine <> z3 then begin
              incr failures;
              Printf.printf
                "[FAIL]  %-24s subject %-16s matcher=%b z3=%b\n" pattern subject
                mine z3
            end)
          subjects;
        Printf.printf "[ok]    %-24s (%d subjects agree)\n" pattern
          (List.length subjects))
    cases;
  List.iter
    (fun (pattern, what) ->
      match Regex.parse pattern with
      | Error _ -> Printf.printf "[ok]    rejected: %-22s (%s)\n" pattern what
      | Ok _ ->
        incr failures;
        Printf.printf "[FAIL]  %-24s must be rejected (%s)\n" pattern what)
    must_reject;
  if !failures > 0 then (
    Printf.printf "\n%d disagreement(s)\n" !failures;
    exit 1)
  else Printf.printf "\nmatcher and z3 agree on every case\n"
