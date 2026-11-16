#!/usr/bin/env python3
"""Bounded synthetic sequence evaluation; no dependency beyond Python and CLI/Z3."""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import statistics
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from generate import cases, SEQUENCE  # noqa: E402

FORMAT_VERSION = 1
MAX_OUTPUT = 8 * 1024 * 1024
RESULTS = {"valid_sequence", "authorization_failed", "contract_failed",
           "invariant_failed", "out_of_scope_regression", "unknown"}
PHASES = {"preparation", "authorization", "final_verification", "state_invariants",
          "intermediate_preservation", "complete"}
PROFILE = "kubernetes-rbac-v1.34-policy-sequence-v"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(value):
    def pairs(entries):
        result = {}
        for key, item in entries:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = item
        return result

    def constant(value):
        raise ValueError("nonfinite JSON value: " + value)

    return json.loads(value, object_pairs_hook=pairs, parse_constant=constant)


def file_record(path):
    data = path.read_bytes()
    return {"sha256": digest(data), "bytes": len(data)}


def write_json(path, value):
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, ensure_ascii=True)
        output.write("\n")


def now():
    return datetime.now(timezone.utc).isoformat()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def tool(path):
    resolved = Path(path).expanduser().resolve(strict=True)
    require(resolved.is_file() and os.access(resolved, os.X_OK), "tool is not an executable file: " + str(resolved))
    return {"path": str(resolved), **file_record(resolved)}


def source_records():
    directory = Path(__file__).resolve().parent
    return {str(p): file_record(p) for p in sorted(directory.iterdir())
            if p.is_file() and p.suffix in {".py", ".md"}}


def verify_record(path, expected):
    require(path.is_file() and not path.is_symlink(), "artifact is missing, nonregular or a symlink: " + str(path))
    require(file_record(path) == expected, "artifact changed: " + str(path))


def bounded_process(command, *, env, timeout, limit):
    """Bound memory and wall time, terminating the process group including Z3."""
    start = time.monotonic()
    result = {"attempted": True, "duration_seconds": 0.0, "exit_code": None,
              "status": "completed", "stdout": b"", "stderr": b""}
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=env, start_new_session=True)
    except OSError as error:
        result.update(status="launch_error", error=str(error), duration_seconds=time.monotonic() - start)
        return result
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = timeout - (time.monotonic() - start)
                if remaining <= 0:
                    result["status"] = "timeout"
                    break
                for key, _ in selector.select(min(0.05, remaining)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    available = limit - total
                    outputs[key.data].extend(chunk[:max(0, available)])
                    total += len(chunk)
                    if total > limit:
                        result["status"] = "output_limit"
                        break
                if result["status"] != "completed":
                    break
            remaining = timeout - (time.monotonic() - start)
            if result["status"] == "completed":
                try:
                    process.wait(timeout=max(0.001, remaining))
                except subprocess.TimeoutExpired:
                    result["status"] = "timeout"
    finally:
        if result["status"] != "completed" or process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        process.stdout.close()
        process.stderr.close()
    result.update(stdout=bytes(outputs["stdout"]), stderr=bytes(outputs["stderr"]),
                  exit_code=process.returncode, duration_seconds=time.monotonic() - start)
    return result


def prepare(output, binary, z3, tier, budgets):
    """Freeze all constructions and expectations before starting Soundcheck."""
    require(not output.exists(), "output directory already exists; choose a new directory")
    executable, solver = tool(binary), tool(z3)
    require(Path(z3).name == "z3", "--z3 must name an executable called z3")
    # Preserve the requested z3 directory even when Homebrew resolves its symlink.
    solver["invocation_path"] = str(Path(z3).expanduser().absolute())
    environment = dict(os.environ, PATH=str(Path(z3).expanduser().absolute().parent) + os.pathsep + os.environ.get("PATH", ""))
    probe = bounded_process([solver["invocation_path"], "-version"], env=environment, timeout=5.0, limit=4096)
    require(probe["status"] == "completed" and probe["exit_code"] == 0, "cannot establish Z3 version")
    solver["version"] = probe["stdout"].decode("utf-8", errors="strict").strip()
    require(solver["version"].startswith("Z3 version "), "unexpected Z3 version response")
    output.mkdir(parents=True, mode=0o700)
    frozen = []
    for case in cases(tier):
        directory = output / "inputs" / case["id"]
        directory.mkdir(parents=True)
        inputs = {}
        for kind in ["before", "after", "contract"]:
            path = directory / (kind + ".json")
            write_json(path, case[kind])
            inputs[kind] = {"path": str(path.relative_to(output)), **file_record(path)}
        frozen.append({key: case[key] for key in ["id", "dimensions", "expected", "rationale"]} | {"inputs": inputs})
    manifest = {"format_version": FORMAT_VERSION, "kind": "soundcheck-rbac-transition-stress-plan",
                "created_utc": now(), "tier": tier, "synthetic": True,
                "budgets": budgets, "tools": {"soundcheck": executable, "z3": solver},
                "sources": source_records(), "cases": frozen,
                "timing_scope": "Every attempted process, including failed or censored runs; no worst-case or live-deployment claim."}
    write_json(output / "before-execution.json", manifest)
    print("Frozen plan:", output / "before-execution.json", digest((output / "before-execution.json").read_bytes()), flush=True)
    return manifest


def normalized_contract(value):
    """Compare this corpus's literal contracts modulo declared set ordering.

    This is not an RBAC parser or an oracle. No selector/default inference is
    performed; the generator uses explicit fields and literal scalar scopes.
    """
    value = deepcopy(value)
    value["invariants"] = sorted(value["invariants"])
    requirements = value["requirements"]
    requirements["change_scope"] = sorted(requirements["change_scope"], key=canonical)
    return value


def object_keys(value, required, label, optional=()):
    require(type(value) is dict, label + " must be an object")
    require(set(required) <= set(value) <= set(required) | set(optional), label + " has missing/unexpected fields")


def core_report(value, *, frozen=None):
    required = {"schema_version", "result", "property", "assurance", "frozen_spec", "clause", "counterexample"}
    object_keys(value, required, "nested report", {"reason"})
    require(type(value["schema_version"]) is int and value["schema_version"] == 10, "unsupported nested report schema")
    require(value["result"] in {"proved", "violated", "vacuous", "inconsistent", "unknown"}, "invalid nested verdict")
    require((value["counterexample"] is not None) == (value["result"] == "violated"), "nested witness/verdict mismatch")
    require(("reason" in value) == (value["result"] in {"inconsistent", "unknown"}), "nested reason/verdict mismatch")
    if frozen is not None:
        require(value["frozen_spec"] == frozen, "wrong nested frozen identity")


def validate_report(report, case, inputs, exit_code):
    required = {"schema_version", "kind", "result", "reason", "phase", "failing_step", "assurance", "frozen_spec",
                "inputs", "states", "steps", "verification", "intermediate_preservation"}
    version = 1 if case["expected"]["phase"] == "preparation" else 2
    if version == 2:
        required.add("state_invariants")
    object_keys(report, required, "sequence report")
    require(type(report["schema_version"]) is int and report["schema_version"] == version and report["kind"] == SEQUENCE, "wrong report kind/version")
    require(report["result"] in RESULTS and report["phase"] in PHASES, "unknown result/phase")
    require(type(report["reason"]) is str, "reason is not a string")
    require(report["failing_step"] is None or type(report["failing_step"]) is int, "invalid failing step")
    require(type(exit_code) is int and exit_code == (0 if report["result"] == "valid_sequence" else
            4 if report["result"] == "unknown" else 3), "exit/result mismatch for this corpus")
    require(report["assurance"] == {"profile": PROFILE + str(version),
            "status": "unsupported_or_inconclusive" if report["result"] == "unknown" else "within_profile"}, "wrong assurance")
    require(report["inputs"] == {k: {"sha256": digest(inputs[k]), "bytes": len(inputs[k])} for k in ["before", "after"]}, "input digest mismatch")
    if version == 1:
        require(report["frozen_spec"] is None and report["result"] == "unknown" and report["phase"] == "preparation", "invalid contract yielded later stages")
        require(report["states"] == [] and report["steps"] == [] and report["verification"] is None
                and report["intermediate_preservation"] == [], "rejected contract carries execution")
    else:
        contract = strict_json(inputs["contract"])
        frozen = report["frozen_spec"]
        object_keys(frozen, {"schema_version", "kind", "canonical"}, "frozen spec")
        require(frozen["schema_version"] == 2 and frozen["kind"] == SEQUENCE and type(frozen["canonical"]) is str, "wrong frozen spec")
        require(normalized_contract(strict_json(frozen["canonical"])) == normalized_contract(contract), "wrong frozen contract")
        n = len(contract["steps"])
        require(type(report["states"]) is list and len(report["states"]) == n + 1, "incomplete state plan")
        require(type(report["steps"]) is list and len(report["steps"]) == n, "incomplete operation plan")
        for i, state in enumerate(report["states"]):
            object_keys(state, {"index", "digest"}, "state")
            require(state["index"] == i, "state index mismatch")
            object_keys(state["digest"], {"sha256", "bytes"}, "state digest")
            require(type(state["digest"]["bytes"]) is int and state["digest"]["bytes"] >= 0
                    and type(state["digest"]["sha256"]) is str and re.fullmatch("[a-f0-9]{64}", state["digest"]["sha256"]), "invalid state digest")
        require(report["states"][0]["digest"] == report["inputs"]["before"] and
                report["states"][-1]["digest"] == report["inputs"]["after"], "state endpoint mismatch")
        for i, (entry, declared) in enumerate(zip(report["steps"], contract["steps"]), 1):
            object_keys(entry, {"index", "operation", "target", "inputs", "authorization"}, "operation")
            require(entry["index"] == i and entry["operation"] == declared["operation"] and entry["target"] == declared["target"], "wrong operation")
            require(entry["inputs"] == {"before": report["states"][i - 1]["digest"], "after": report["states"][i]["digest"]}, "operation chain mismatch")
            authorization = entry["authorization"]
            failure = report["failing_step"] if report["phase"] == "authorization" else n + 1
            if i > failure:
                require(authorization is None, "authorization after failure must be skipped")
            else:
                require(type(authorization) is dict and type(authorization.get("allowed")) is bool, "authorization is missing")
                require(authorization["allowed"] == (i < failure), "authorization prefix disagrees with failure")
        verification = report["verification"]
        if report["phase"] == "authorization":
            require(verification is None, "verification before all authorization succeeded")
        else:
            object_keys(verification, {"comparison_report", "candidate_report"}, "verification")
            core_report(verification["comparison_report"])
            core_report(verification["candidate_report"])
            if report["result"] != "contract_failed":
                require(verification["candidate_report"]["result"] == "proved", "final requirements did not pass")
            else:
                require(verification["candidate_report"]["result"] == "violated", "missing final requirement violation")
            if report["phase"] in {"complete", "state_invariants", "intermediate_preservation"}:
                require(verification["comparison_report"]["result"] == "proved", "incoherent final comparison")
            elif report["result"] == "out_of_scope_regression":
                require(verification["comparison_report"]["result"] == "violated", "missing preservation violation")
        invariant_states = range(n + 1) if contract["invariants"] else range(0)
        require(type(report["state_invariants"]) is list and len(report["state_invariants"]) == len(invariant_states), "incomplete invariant plan")
        for i, entry in zip(invariant_states, report["state_invariants"]):
            object_keys(entry, {"state", "input", "status", "report"}, "state invariant")
            require(entry["state"] == i and entry["input"] == report["states"][i]["digest"], "invariant state mismatch")
            if report["phase"] in {"authorization", "final_verification"} or (report["phase"] == "state_invariants" and i > report["failing_step"]):
                require(entry["status"] == "not_executed" and entry["report"] is None, "skipped invariant claimed a result")
            else:
                wanted = "violated" if report["phase"] == "state_invariants" and i == report["failing_step"] else "proved"
                require(entry["status"] == wanted, "wrong invariant outcome")
                core_report(entry["report"], frozen=frozen)
                require(entry["report"]["result"] == wanted, "invariant status/report mismatch")
                if wanted == "violated":
                    require(entry["report"]["clause"]["name"] in contract["invariants"], "failure is not a selected invariant")
        require(type(report["intermediate_preservation"]) is list and len(report["intermediate_preservation"]) == n - 1, "incomplete preservation plan")
        for i, entry in enumerate(report["intermediate_preservation"], 1):
            object_keys(entry, {"step", "inputs", "status", "report"}, "preservation")
            require(entry["step"] == i and entry["inputs"] == {"before": report["inputs"]["before"], "after": report["states"][i]["digest"]}, "preservation chain mismatch")
            if report["phase"] == "complete":
                require(entry["status"] == "proved", "successful sequence lacks preservation")
                core_report(entry["report"])
                require(entry["report"]["result"] == "proved", "preservation status/report mismatch")
            else:
                require(entry["status"] == "not_executed" and entry["report"] is None, "skipped preservation claimed a result")
    expected = case["expected"]
    actual = {"result": report["result"], "phase": report["phase"], "failing_step": report["failing_step"], "exit_code": exit_code}
    require(actual == {k: expected[k] for k in actual}, "outcome differs from frozen expectation: " + canonical(actual))
    if "reason_contains" in expected:
        require(expected["reason_contains"] in report["reason"], "unexpected unsupported-boundary reason")
    return actual


def inputs_for(output, case):
    result = {}
    for name, entry in case["inputs"].items():
        relative = Path(entry["path"])
        require(not relative.is_absolute() and ".." not in relative.parts and relative.parts[:1] == ("inputs",), "unsafe input path")
        path = output / relative
        require(path.resolve().is_relative_to(output.resolve()), "input path escapes output")
        verify_record(path, {k: entry[k] for k in ["sha256", "bytes"]})
        result[name] = path.read_bytes()
    return result


def verify_tools(manifest):
    for entry in manifest["tools"].values():
        require(file_record(Path(entry["path"])) == {k: entry[k] for k in ["sha256", "bytes"]}, "tool changed: " + entry["path"])
    solver = manifest["tools"]["z3"]
    require(Path(solver["invocation_path"]).resolve() == Path(solver["path"]), "Z3 invocation changed")
    for path, expected in manifest["sources"].items():
        verify_record(Path(path), expected)


def execute(output, binary):
    plan_path = output / "before-execution.json"
    require(plan_path.is_file() and not plan_path.is_symlink(), "prepared plan missing or symlinked")
    plan_bytes = plan_path.read_bytes()
    manifest = strict_json(plan_bytes)
    require(manifest["format_version"] == FORMAT_VERSION and manifest["kind"] == "soundcheck-rbac-transition-stress-plan", "unknown plan format")
    require(manifest["tier"] in {"smoke", "full"} and len(manifest["cases"]) == (8 if manifest["tier"] == "smoke" else 16), "wrong scheduled count")
    require(tool(binary) == manifest["tools"]["soundcheck"], "binary differs from frozen plan")
    budgets = manifest["budgets"]
    validate_budgets(budgets)
    require(not (output / "execution-started.json").exists() and not (output / "results.json").exists(), "prepared plan was already executed; choose a fresh output directory")
    # The generator's expected outcomes and exact bytes must still be the frozen
    # construction, even if someone edited both input and its manifest digest.
    for declared, generated in zip(manifest["cases"], cases(manifest["tier"])):
        require({k: declared[k] for k in ["id", "expected", "rationale", "dimensions"]} ==
                {k: generated[k] for k in ["id", "expected", "rationale", "dimensions"]}, "modified construction/expectation")
        data = inputs_for(output, declared)
        require(all(strict_json(data[k]) == generated[k] for k in data), "modified generated input")
    verify_tools(manifest)
    write_json(output / "execution-started.json", {"started_utc": now(), "plan_sha256": digest(plan_bytes)})
    started = time.monotonic()
    solver = manifest["tools"]["z3"]
    environment = dict(os.environ, PATH=str(Path(solver["invocation_path"]).parent) + os.pathsep + os.environ.get("PATH", ""))
    observations = []
    for case in manifest["cases"]:
        remaining = budgets["total_seconds"] - (time.monotonic() - started)
        observation = {"id": case["id"], "expected": case["expected"], "dimensions": case["dimensions"],
                       "attempted": False, "duration_seconds": None, "exit_code": None,
                       "status": "budget_skipped", "matched": False, "actual": None}
        if remaining > 0:
            directory = output / "runs" / case["id"]
            directory.mkdir(parents=True)
            try:
                verify_tools(manifest)
                require(plan_path.read_bytes() == plan_bytes, "frozen plan changed during execution")
                inputs = inputs_for(output, case)
                command = [manifest["tools"]["soundcheck"]["path"], "rbac", "sequence",
                           str(output / case["inputs"]["before"]["path"]), str(output / case["inputs"]["after"]["path"]),
                           "--contract", str(output / case["inputs"]["contract"]["path"]), "--format", "json"]
                observation["command"] = command
                remaining = budgets["total_seconds"] - (time.monotonic() - started)
                if remaining <= 0:
                    observations.append(observation)
                    print(case["id"] + ": budget_skipped", flush=True)
                    continue
                result = bounded_process(command, env=environment, timeout=min(budgets["per_run_seconds"], remaining), limit=budgets["output_bytes"])
                stdout, stderr = result.pop("stdout"), result.pop("stderr")
                observation.update(result)
                for name, content in [("stdout", stdout), ("stderr", stderr)]:
                    path = directory / (name + ".txt")
                    path.write_bytes(content)
                    observation[name] = {"path": str(path.relative_to(output)), **file_record(path)}
                inputs_for(output, case)
                verify_tools(manifest)
                require(plan_path.read_bytes() == plan_bytes, "frozen plan changed during execution")
                if observation["status"] == "completed":
                    try:
                        report = strict_json(stdout.decode("utf-8", errors="strict"))
                        observation["actual"] = validate_report(report, case, inputs, observation["exit_code"])
                        observation["matched"] = True
                    except (ValueError, TypeError, KeyError, UnicodeError) as error:
                        observation.update(status="protocol_or_expectation_failure", error=str(error))
            except (OSError, ValueError, TypeError, KeyError) as error:
                observation.update(status="integrity_or_io_failure", error=str(error))
        observations.append(observation)
        print(case["id"] + ": " + ("matched" if observation["matched"] else observation["status"]), flush=True)
    durations = [entry["duration_seconds"] for entry in observations if entry["duration_seconds"] is not None]
    counts = {status: sum(o["status"] == status for o in observations) for status in sorted({o["status"] for o in observations})}
    complete = all(entry["matched"] for entry in observations)
    summary = {"format_version": FORMAT_VERSION, "kind": "soundcheck-rbac-transition-stress-results",
               "finished_utc": now(), "plan": {"path": "before-execution.json", "sha256": digest(plan_bytes)},
               "tier": manifest["tier"], "synthetic": True, "complete": complete,
               "scheduled": len(observations), "attempted": sum(o["attempted"] for o in observations),
               "matched": sum(o["matched"] for o in observations), "status_counts": counts,
               "total_seconds": time.monotonic() - started,
               "all_attempt_timings": {"count": len(durations), "sum_seconds": sum(durations),
                                      "median_seconds": statistics.median(durations) if durations else None,
                                      "max_seconds": max(durations) if durations else None,
                                      "includes_failures_and_timeout_lower_bounds": True},
               "observations": observations}
    write_json(output / "results.json", summary)
    return 0 if complete else 1


def validate_budgets(budgets):
    require(set(budgets) == {"per_run_seconds", "total_seconds", "output_bytes"}, "invalid budget fields")
    for key, maximum in [("per_run_seconds", 60), ("total_seconds", 600)]:
        value = budgets[key]
        require(type(value) in {int, float} and math.isfinite(value) and 0 < value <= maximum, "invalid " + key)
    require(type(budgets["output_bytes"]) is int and 1024 <= budgets["output_bytes"] <= MAX_OUTPUT, "invalid output_bytes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--z3", type=Path, default=shutil.which("z3"))
    parser.add_argument("--tier", choices=["smoke", "full"], default="smoke")
    parser.add_argument("--output", type=Path, required=True)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--prepare-only", action="store_true")
    action.add_argument("--execute-prepared", action="store_true")
    parser.add_argument("--per-run-seconds", type=float, default=60.0)
    parser.add_argument("--total-seconds", type=float, default=600.0)
    parser.add_argument("--output-bytes", type=int, default=MAX_OUTPUT)
    args = parser.parse_args()
    try:
        output = args.output.expanduser().absolute()
        if not args.execute_prepared:
            require(args.z3 is not None, "z3 not found; pass --z3")
            budgets = {"per_run_seconds": args.per_run_seconds, "total_seconds": args.total_seconds, "output_bytes": args.output_bytes}
            validate_budgets(budgets)
            prepare(output, args.binary, args.z3, args.tier, budgets)
        return 0 if args.prepare_only else execute(output, args.binary)
    except (ValueError, OSError, KeyError, TypeError) as error:
        print("transition stress error: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
