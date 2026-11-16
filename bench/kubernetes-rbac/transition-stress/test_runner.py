"""Harness boundary tests; these do not pretend to prove RBAC semantics."""

from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate
import run


class StressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.binary = self.script("soundcheck", "print('{}')\n")
        self.z3 = self.script("z3", "print('Z3 version test - 64 bit')\n")
        self.budgets = {"per_run_seconds": 1, "total_seconds": 5, "output_bytes": 4096}

    def tearDown(self):
        self.temp.cleanup()

    def script(self, name, body):
        path = self.root / name
        path.write_text("#!" + sys.executable + "\n" + body)
        path.chmod(0o700)
        return path

    def prepared(self, budgets=None):
        path = self.root / "out"
        with redirect_stdout(io.StringIO()):
            plan = run.prepare(path, self.binary, self.z3, "smoke", budgets or self.budgets)
        return path, plan

    def test_deterministic_construction_dimensions(self):
        self.assertEqual(generate.cases("full"), generate.cases("full"))
        self.assertEqual(len(generate.cases("smoke")), 8)
        full = generate.cases("full")
        self.assertEqual(len(full), 16)
        self.assertEqual(len({c["id"] for c in full}), 16)
        self.assertTrue({1, 4, 8, 16} <= {c["dimensions"]["steps"] for c in full})
        self.assertEqual(max(c["dimensions"]["identities"] for c in full), 16)
        self.assertEqual(max(c["dimensions"]["clauses"] for c in full), 16)
        self.assertEqual(max(c["dimensions"]["background_role_binding_pairs"] for c in full), 128)
        for case in full:
            self.assertEqual(case["dimensions"]["objects_before"], len(case["before"]["items"]))
            self.assertEqual(case["dimensions"]["objects_after"], len(case["after"]["items"]))
            self.assertEqual(case["dimensions"]["selected_clauses"], len(case["contract"]["invariants"]))

    def test_construction_failure_causes_are_present(self):
        values = {c["id"]: c for c in generate.cases("full")}
        gap = values["temporary-loss"]["contract"]["steps"]
        self.assertEqual((gap[1]["operation"], gap[1]["target"]["kind"]), ("delete-existing", "RoleBinding"))
        self.assertEqual((gap[2]["operation"], gap[2]["target"]["kind"]), ("create", "RoleBinding"))
        grant = values["temporary-grant"]
        before = next(x for x in grant["before"]["items"] if x["kind"] == "Role" and x["metadata"]["name"] == "transient")
        after = next(x for x in grant["after"]["items"] if x["kind"] == "Role" and x["metadata"]["name"] == "transient")
        self.assertEqual(before["rules"], [])
        self.assertEqual(after["rules"][0]["resources"], ["secrets"])
        self.assertEqual(grant["contract"]["steps"][1]["operation"], "delete-existing")
        revoked = values["actor-revoked"]
        self.assertTrue(any(o["kind"] == "ClusterRoleBinding" for o in revoked["before"]["items"]))
        self.assertFalse(any(o["kind"] == "ClusterRoleBinding" for o in revoked["after"]["items"]))
        outside = values["outside-scope"]
        self.assertFalse(any(s["resource"] == "pods" for s in outside["contract"]["requirements"]["change_scope"]))
        self.assertTrue(any("pods" in rule["resources"] for o in outside["before"]["items"] if o["kind"] == "Role" for rule in o["rules"]))

    def test_plan_precedes_every_attempt_and_inputs_are_hashed(self):
        output, plan = self.prepared()
        self.assertTrue((output / "before-execution.json").is_file())
        self.assertFalse((output / "runs").exists())
        self.assertEqual(len(plan["cases"]), 8)
        for case in plan["cases"]:
            self.assertEqual(set(run.inputs_for(output, case)), {"before", "after", "contract"})
        with redirect_stdout(io.StringIO()):
            self.assertEqual(run.execute(output, self.binary), 1)
        summary = json.loads((output / "results.json").read_text())
        self.assertFalse(summary["complete"])
        self.assertEqual(summary["scheduled"], 8)
        self.assertEqual(summary["attempted"], 8)
        self.assertEqual(summary["all_attempt_timings"]["count"], 8)
        self.assertEqual(summary["status_counts"], {"protocol_or_expectation_failure": 8})
        self.assertTrue(all(o["stdout"]["sha256"] and o["stderr"]["sha256"] for o in summary["observations"]))

    def test_existing_directory_and_reexecution_refused(self):
        output, _ = self.prepared()
        with self.assertRaisesRegex(ValueError, "already exists"):
            run.prepare(output, self.binary, self.z3, "smoke", self.budgets)
        with redirect_stdout(io.StringIO()):
            run.execute(output, self.binary)
        before = (output / "results.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "already executed"):
            run.execute(output, self.binary)
        self.assertEqual(before, (output / "results.json").read_bytes())

    def test_changed_input_and_changed_expectation_refused(self):
        output, plan = self.prepared()
        path = output / plan["cases"][0]["inputs"]["before"]["path"]
        path.write_text("{}")
        with self.assertRaisesRegex(ValueError, "artifact changed"):
            run.execute(output, self.binary)
        self.assertFalse((output / "execution-started.json").exists())

    def test_matching_rehashed_input_tampering_still_refused(self):
        output, plan = self.prepared()
        entry = plan["cases"][0]["inputs"]["before"]
        path = output / entry["path"]
        path.write_text("{}")
        entry.update(run.file_record(path))
        (output / "before-execution.json").write_text(json.dumps(plan))
        with self.assertRaisesRegex(ValueError, "modified generated input"):
            run.execute(output, self.binary)

    def test_expectation_tampering_refused(self):
        output, plan = self.prepared()
        plan["cases"][0]["expected"]["result"] = "unknown"
        (output / "before-execution.json").write_text(json.dumps(plan))
        with self.assertRaisesRegex(ValueError, "modified construction/expectation"):
            run.execute(output, self.binary)

    def test_binary_and_source_tampering_refused(self):
        output, plan = self.prepared()
        self.binary.write_text(self.binary.read_text() + "# changed\n")
        with self.assertRaisesRegex(ValueError, "binary differs"):
            run.execute(output, self.binary)
        victim = self.root / "source.py"
        victim.write_text("pass\n")
        plan["sources"] = {str(victim): run.file_record(victim)}
        victim.write_text("raise Exception()\n")
        with self.assertRaises(ValueError):
            run.verify_tools(plan)

    def test_input_symlink_and_parent_path_refused(self):
        output, plan = self.prepared()
        case = plan["cases"][0]
        path = output / case["inputs"]["after"]["path"]
        saved = self.root / "candidate.json"
        saved.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(saved)
        with self.assertRaises(ValueError):
            run.inputs_for(output, case)
        case["inputs"]["after"]["path"] = "../candidate.json"
        with self.assertRaisesRegex(ValueError, "unsafe input path"):
            run.inputs_for(output, case)

    def test_process_timeout_output_limit_and_launch_error(self):
        sleeper = self.script("sleeper", "import time\ntime.sleep(5)\n")
        result = run.bounded_process([str(sleeper)], env=os.environ, timeout=0.05, limit=1024)
        self.assertEqual(result["status"], "timeout")
        self.assertLess(result["duration_seconds"], 2)
        loud = self.script("loud", "import os\nwhile True: os.write(1,b'x'*4096)\n")
        result = run.bounded_process([str(loud)], env=os.environ, timeout=1, limit=1024)
        self.assertEqual(result["status"], "output_limit")
        self.assertLessEqual(len(result["stdout"]) + len(result["stderr"]), 1024)
        result = run.bounded_process([str(self.root / "missing")], env=os.environ, timeout=1, limit=1024)
        self.assertEqual(result["status"], "launch_error")

    def test_timeout_terminates_descendant_process(self):
        marker = self.root / "late"
        child = self.script("child", "import time\nfrom pathlib import Path\ntime.sleep(.3)\nPath(" + repr(str(marker)) + ").write_text('leaked')\n")
        parent = self.script("parent", "import subprocess,time\nsubprocess.Popen([" + repr(str(child)) + "])\ntime.sleep(5)\n")
        result = run.bounded_process([str(parent)], env=os.environ, timeout=.05, limit=1024)
        self.assertEqual(result["status"], "timeout")
        # A separate process waits beyond the child's scheduled write.
        run.bounded_process([sys.executable, "-c", "import time;time.sleep(.35)"], env=os.environ, timeout=1, limit=1024)
        self.assertFalse(marker.exists())

    def test_total_budget_retains_all_scheduled_rows(self):
        self.binary.write_text("#!" + sys.executable + "\nimport time\ntime.sleep(5)\n")
        output, _ = self.prepared({"per_run_seconds": .04, "total_seconds": .06, "output_bytes": 1024})
        with redirect_stdout(io.StringIO()):
            self.assertEqual(run.execute(output, self.binary), 1)
        summary = json.loads((output / "results.json").read_text())
        self.assertEqual(summary["scheduled"], 8)
        self.assertEqual(len(summary["observations"]), 8)
        self.assertIn("timeout", summary["status_counts"])
        self.assertIn("budget_skipped", summary["status_counts"])
        self.assertEqual(summary["attempted"], summary["all_attempt_timings"]["count"])
        self.assertFalse(summary["complete"])

    def test_budget_validation(self):
        for key, value in [("per_run_seconds", 61), ("per_run_seconds", float("nan")),
                           ("total_seconds", 601), ("total_seconds", 0), ("output_bytes", 1023),
                           ("output_bytes", 8 * 1024 * 1024 + 1)]:
            budgets = dict(self.budgets, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                run.validate_budgets(budgets)

    def test_strict_json_rejects_duplicate_nonfinite_and_trailing_values(self):
        for text in ['{"result":"unknown","result":"valid_sequence"}', '{"x":NaN}',
                     '{"x":Infinity}', '{}{}']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                run.strict_json(text)

    @staticmethod
    def rejected_report():
        case = generate.cases("smoke")[-1]
        inputs = {key: json.dumps(case[key]).encode() for key in ["before", "after", "contract"]}
        report = {"schema_version": 1, "kind": generate.SEQUENCE, "result": "unknown",
                  "phase": "preparation", "reason": "duplicate target", "failing_step": None,
                  "assurance": {"profile": run.PROFILE + "1", "status": "unsupported_or_inconclusive"},
                  "frozen_spec": None, "inputs": {key: {"sha256": run.digest(inputs[key]), "bytes": len(inputs[key])}
                                                   for key in ["before", "after"]},
                  "states": [], "steps": [], "verification": None, "intermediate_preservation": []}
        return report, case, inputs

    def test_typed_rejection_and_protocol_corruption(self):
        report, case, inputs = self.rejected_report()
        self.assertEqual(run.validate_report(report, case, inputs, 4)["result"], "unknown")
        for change in [lambda r: r.update(schema_version=3), lambda r: r.update(extra=True),
                       lambda r: r.update(result="valid_sequence"), lambda r: r.update(reason="wrong reason"),
                       lambda r: r["inputs"]["before"].update(sha256="0" * 64),
                       lambda r: r.update(states=[{}]), lambda r: r.update(verification={})]:
            modified = deepcopy(report)
            change(modified)
            with self.assertRaises((ValueError, KeyError, TypeError)):
                run.validate_report(modified, case, inputs, 4)
        with self.assertRaisesRegex(ValueError, "exit/result mismatch"):
            run.validate_report(report, case, inputs, 0)


if __name__ == "__main__":
    unittest.main()
