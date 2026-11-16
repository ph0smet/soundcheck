#!/usr/bin/env python3
"""Exercise the packaged RBAC HTTP adapter with repository-owned synthetic inputs."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import urllib.error
import urllib.parse
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "bench/kubernetes-rbac/workflows/policy-retirement"
MAX_RESPONSE = 32 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def document(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


def request(url, route, body=None, origin=None):
    headers = {"content-type": "application/json"}
    if origin:
        headers["origin"] = origin
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url + route, data=data, headers=headers)
    try:
        response = urllib.request.urlopen(req, timeout=120)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(MAX_RESPONSE + 1)
        require(len(raw) <= MAX_RESPONSE, "HTTP response exceeded the smoke-test budget")
        return response.status, raw


def post(url, route, body, origin=None):
    status, raw = request(url, route, body, origin)
    return status, json.loads(raw)


def check_archive(response):
    archive = response["evidenceArchive"]
    require(archive["mediaType"] == "application/zip", "wrong evidence media type")
    raw = base64.b64decode(archive["base64"], validate=True)
    require(len(raw) == archive["bytes"], "archive byte count mismatch")
    require(digest(raw) == archive["sha256"], "archive SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
        files = bundle.infolist()
        names = [entry.filename for entry in files]
        require(len(files) == archive["fileCount"] and len(set(names)) == len(names),
                "archive count or duplicate path mismatch")
        require(sum(entry.file_size for entry in files) <= 64 * 1024 * 1024,
                "expanded evidence exceeded its bound")
        for entry in files:
            path = PurePosixPath(entry.filename)
            require(not path.is_absolute() and ".." not in path.parts
                    and "\\" not in entry.filename and not entry.is_dir(),
                    "unsafe archive path")
            require(not stat.S_ISLNK(entry.external_attr >> 16), "archive contains a symlink")
        require(bundle.testzip() is None, "archive CRC mismatch")
        require(json.loads(bundle.read("report.json")) == response["report"],
                "downloaded report differs from the displayed report")
    return len(files)


def run(url, mode, contract, candidate, baseline=None, expected="proved", exit_code=0):
    context = {"mode": mode, "contract": contract}
    if baseline is not None:
        context["baseline"] = baseline
    status, reviewed = post(url, "/api/rbac/review", context)
    require(status == 200 and reviewed.get("ok") is True,
            f"{mode}: review failed: {reviewed}")
    review = reviewed["review"]
    require(review["contractSha256"] == digest(contract.encode()), "wrong reviewed contract")
    require(review["baselineSha256"] == (digest(baseline.encode()) if baseline is not None else None),
            "wrong reviewed baseline")
    payload = {**context, "candidate": candidate, "reviewed": {
        "contractSha256": review["contractSha256"],
        "baselineSha256": review["baselineSha256"],
    }}
    status, response = post(url, "/api/rbac/run", payload)
    require(status == 200 and response.get("ok") is True,
            f"{mode}: verification failed: {response}")
    require(response["mode"] == mode and response["report"]["result"] == expected
            and response["exitCode"] == exit_code, f"{mode}: unexpected outcome")
    inputs = response["provenance"]["inputs"]
    for source in [contract, candidate] + ([baseline] if baseline is not None else []):
        require(digest(source.encode()) in inputs.values(), f"{mode}: missing input provenance")
    count = check_archive(response)
    print(f"{mode}: {expected}; {count} evidence files checked", flush=True)
    return payload, response


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:3000")
    args = parser.parse_args()
    url = args.url.rstrip("/")
    parts = urllib.parse.urlsplit(url)
    require(parts.scheme == "http" and parts.hostname in {"localhost", "127.0.0.1", "::1"}
            and not parts.path and not parts.query and not parts.fragment
            and parts.username is None, "smoke URL must be a local HTTP origin")
    status, page = request(url, "/rbac")
    require(status == 200 and b"RBAC" in page, "RBAC page is unavailable")
    contract, before, after = document("contract.json"), document("before.json"), document("repaired.json")
    access = json.dumps(json.loads(contract)["requirements"])
    run(url, "verify", access, after)
    run(url, "repair", access, after, before)
    run(url, "change", document("delete-contract.json"), document("delete-after.json"),
        document("delete-before.json"), "valid_change")
    payload, _ = run(url, "sequence", contract, after, before, "valid_sequence")
    _, failed = run(url, "sequence", document("gap-contract.json"), after, before,
                    "invariant_failed", 3)
    require(failed["report"]["phase"] == "state_invariants"
            and failed["report"]["failing_step"] == 1, "wrong failed migration state")
    tampered = {**payload, "reviewed": {**payload["reviewed"], "contractSha256": "0" * 64}}
    status, rejected = post(url, "/api/rbac/run", tampered)
    require(status in {200, 400} and rejected.get("ok") is False
            and rejected.get("stage") == "input", "changed reviewed context was accepted")
    status, rejected = post(url, "/api/rbac/run", payload, "https://evil.example")
    require(status == 403 and rejected.get("ok") is False, "cross-origin RBAC run was accepted")
    print("RBAC HTTP smoke passed: four modes, failing invariant, context and origin guards.")


if __name__ == "__main__":
    main()
