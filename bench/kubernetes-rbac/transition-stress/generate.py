"""Deterministic constructions, independent of the verifier's answers."""

from copy import deepcopy

RBAC = "rbac.authorization.k8s.io"
SEQUENCE = "kubernetes-rbac-policy-sequence"


def policy(kind, name, namespace=None, **fields):
    metadata = {"name": name}
    if namespace is not None:
        metadata["namespace"] = namespace
    return {"apiVersion": RBAC + "/v1", "kind": kind, "metadata": metadata, **fields}


def rule(resources, verbs=("get",), group=""):
    return {"apiGroups": [group], "resources": list(resources), "verbs": list(verbs)}


def binding(name, role_name, users, namespace=None):
    kind = "ClusterRoleBinding" if namespace is None else "RoleBinding"
    ref_kind = "ClusterRole" if namespace is None else "Role"
    return policy(kind, name, namespace,
                  roleRef={"apiGroup": RBAC, "kind": ref_kind, "name": role_name},
                  subjects=[{"kind": "User", "apiGroup": RBAC, "name": u} for u in users])


def step(operation, obj):
    meta = obj["metadata"]
    return {"operation": operation, "target": {
        "kind": obj["kind"], "namespace": meta.get("namespace"), "name": meta["name"]}}


def scope(user, namespace, resource):
    return {"subject": user, "namespace": namespace, "resource": resource, "names": None,
            "operation": "get", "api_group": "", "subresource": "", "request_kind": "resource"}


def inventory(items):
    return {"apiVersion": "v1", "kind": "List", "items": items}


def expected(result, phase, failing_step=None, reason_contains=None):
    value = {"result": result, "phase": phase, "failing_step": failing_step,
             "exit_code": 0 if result == "valid_sequence" else 4 if result == "unknown" else 3}
    if reason_contains:
        value["reason_contains"] = reason_contains
    return value


def make_case(case_id, *, steps=4, background=0, identities=2, clauses=2,
              variant="valid", select_invariants=True):
    """Only literal grants/subjects; no wildcard, aggregate or approximation.

    Migration units have separate namespaces. Every old binding is replaced
    before retirement except the deliberate gap. Background grants are identical
    and outside the allowed-change scope. Extra forbidden-grant steps create
    unbound roles, so they cannot affect any identity's access.
    """
    assert identities >= 2 and clauses >= 2 and clauses % 2 == 0
    users = [f"client-{i:02}" for i in range(identities - 1)]
    actor_role = policy("ClusterRole", "operator-policy", rules=[
        rule(["roles", "rolebindings"], ["create", "update", "delete", "bind", "escalate"], RBAC),
        rule(["clusterrolebindings"], ["delete"], RBAC)])
    actor_binding = binding("operator-policy", "operator-policy", ["operator"])
    common = [actor_role, actor_binding]
    for i in range(background):
        name = f"background-{i:03}"
        common.extend([policy("Role", name, "background", rules=[rule(["pods"])]),
                       binding(name, name, users, "background")])
    before, after = deepcopy(common), deepcopy(common)
    operations = []
    units = max(1, steps // 4)

    if variant == "forbidden":
        units = 1
        anchor = policy("Role", "anchor", "work-00", rules=[rule(["configmaps"])])
        old = policy("Role", "transient", "work-00", rules=[])
        new = policy("Role", "transient", "work-00", rules=[rule(["secrets"])])
        bound = binding("transient", "transient", users, "work-00")
        stable = [anchor, binding("anchor", "anchor", users, "work-00")]
        before += deepcopy(stable) + [old, bound]
        after += deepcopy(stable) + [new]
        operations = [step("update-existing", new), step("delete-existing", bound)]
        for i in range(steps - 2):
            unused = policy("Role", f"unbound-{i:02}", "work-00", rules=[rule(["pods"])])
            after.append(unused)
            operations.append(step("create", unused))
    elif variant == "revoked":
        units = 1
        stable = [policy("Role", "anchor", "work-00", rules=[rule(["configmaps"])]),
                  binding("anchor", "anchor", users, "work-00")]
        before += deepcopy(stable)
        after = [o for o in after if o["kind"] != "ClusterRoleBinding"] + deepcopy(stable)
        operations = [step("delete-existing", actor_binding)]
        for i in range(steps - 1):
            unused = policy("Role", f"unbound-{i:02}", "work-00", rules=[rule(["pods"])])
            after.append(unused)
            operations.append(step("create", unused))
    else:
        for i in range(units):
            namespace = f"work-{i:02}"
            resources = ["configmaps", "secrets"]
            if variant == "initial" and i == 0:
                resources = ["secrets"]
            if variant == "outside" and i == 0:
                resources.append("pods")
            old = policy("Role", "old-reader", namespace, rules=[rule(resources)])
            bound = binding("old-client", "old-reader", users, namespace)
            before += [old, bound]
            final_resources = ["configmaps", "secrets"] if variant == "final" and i == 0 else ["configmaps"]
            if steps == 1:
                new = policy("Role", "old-reader", namespace, rules=[rule(final_resources)])
                after += [new, deepcopy(bound)]
                operations += [step("update-existing", new)]
            else:
                new = policy("Role", "replacement-reader", namespace, rules=[rule(final_resources)])
                replacement = binding("replacement-client", "replacement-reader", users, namespace)
                after += [new, replacement]
                changes = [step("create", new), step("create", replacement),
                           step("delete-existing", bound), step("delete-existing", old)]
                if variant == "gap" and i == 0:
                    changes[1], changes[2] = changes[2], changes[1]
                operations += changes

    required = []
    for i in range(clauses // 2):
        user, namespace = users[i % len(users)], f"work-{i % units:02}"
        required += [dict(name=f"required-{i:02}", kind="must_allow", **scope(user, namespace, "configmaps")),
                     dict(name=f"forbidden-{i:02}", kind="must_not_grant", **scope(user, namespace, "secrets"))]
    selection = [c["name"] for c in required if c["kind"] == "must_allow"]
    if variant == "forbidden":
        selection = [c["name"] for c in required]
    if not select_invariants:
        selection = []
    requirements = {"schema_version": 10, "kind": "kubernetes-rbac-access",
                    "context": {"schema_version": 1, "snapshot_complete": True,
                                "identities": [{"username": u, "groups": []} for u in users + ["operator"]]},
                    "custom_resources": [], "clauses": required,
                    "change_scope": [scope(u, f"work-{i:02}", resource)
                                     for u in users for i in range(units)
                                     for resource in ["configmaps", "secrets"]]}
    contract = {"schema_version": 2, "kind": SEQUENCE, "actor": "operator",
                "steps": operations, "invariants": selection, "requirements": requirements}
    outcomes = {
        "valid": expected("valid_sequence", "complete"),
        "gap": expected("invariant_failed", "state_invariants", 2),
        "forbidden": expected("invariant_failed", "state_invariants", 1),
        "revoked": expected("authorization_failed", "authorization", 2),
        "outside": expected("out_of_scope_regression", "final_verification", steps),
        "initial": expected("invariant_failed", "state_invariants", 0),
        "final": expected("contract_failed", "final_verification", steps),
    }
    rationale = {
        "valid": "Replacement bindings precede removals. Required ConfigMap grants persist; Secret grants are removed inside scope. Background grants are identical.",
        "gap": "Step 2 removes the only old binding before its replacement. ConfigMap access is absent at S2 and restored at S3; final state meets all requirements.",
        "forbidden": "The initially empty transient role gains Secret get at step 1 while bound to every client. Step 2 removes that binding. An unchanged anchor preserves ConfigMap access throughout.",
        "revoked": "Step 1 removes the operator's only ClusterRoleBinding. The operator consequently has no create Role grant at step 2; authorization precedes all requirement checks.",
        "outside": "Retiring the old role also removes Pod get. Pod access is outside every approved scope; final ConfigMap/Secret clauses still hold.",
        "initial": "The baseline grants Secrets but no ConfigMaps in work-00. The final replacement satisfies both final clauses, but selected required-00 already fails at S0.",
        "final": "The replacement in work-00 retains Secret get. The final forbidden-00 clause fails before invariant checks.",
    }[variant]
    return {"id": case_id, "before": inventory(before), "after": inventory(after), "contract": contract,
            "expected": outcomes[variant], "rationale": rationale,
            "dimensions": {"steps": len(operations), "background_role_binding_pairs": background,
                           "identities": identities, "clauses": clauses,
                           "selected_clauses": len(selection), "objects_before": len(before), "objects_after": len(after)}}


def cases(tier):
    smoke = [
        make_case("valid-one", steps=1),
        make_case("valid-four", background=2, identities=3, clauses=4),
        make_case("temporary-loss", variant="gap"),
        make_case("temporary-grant", variant="forbidden"),
        make_case("actor-revoked", variant="revoked", steps=2),
        make_case("outside-scope", variant="outside"),
    ]
    bound = make_case("seventeen-steps", steps=16)
    unused = policy("Role", "too-many", "work-00", rules=[rule(["pods"])])
    bound["after"]["items"].append(unused)
    bound["contract"]["steps"].append(step("create", unused))
    bound["expected"] = expected("unknown", "preparation", reason_contains="expected 1..16 steps")
    bound["rationale"] = "Seventeen distinct steps exceed the fixed sequence bound; contract rejection must precede policy execution."
    bound["dimensions"].update(steps=17, objects_after=len(bound["after"]["items"]))
    duplicate = make_case("duplicate-target", steps=1)
    duplicate["contract"]["steps"] *= 2
    duplicate["expected"] = expected("unknown", "preparation", reason_contains="duplicate target")
    duplicate["rationale"] = "The same Role target appears twice. Distinct-target sequence contracts must reject this before policy execution."
    duplicate["dimensions"]["steps"] = 2
    smoke += [bound, duplicate]
    if tier == "smoke":
        return smoke
    if tier != "full":
        raise ValueError("tier must be smoke or full")
    return smoke + [
        make_case("valid-eight", steps=8, background=16, identities=4, clauses=8),
        make_case("valid-sixteen", steps=16, background=32, identities=8, clauses=16),
        make_case("inventory-128-pairs", steps=4, background=128, identities=16, clauses=16),
        make_case("sixteen-final-only", steps=16, background=64, identities=16, clauses=16, select_invariants=False),
        make_case("loss-sixteen", steps=16, background=8, identities=4, clauses=4, variant="gap"),
        make_case("grant-sixteen", steps=16, background=16, identities=8, clauses=8, variant="forbidden"),
        make_case("initial-invariant", background=2, variant="initial"),
        make_case("final-requirement", background=4, identities=4, clauses=4, variant="final"),
    ]
