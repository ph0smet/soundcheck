package main

import (
	"strings"
	"testing"
)

const role = `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"reader","namespace":"demo"},"rules":[{"verbs":["get"],"apiGroups":[""],"resources":["pods"]}]}`
const binding = `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"read","namespace":"demo"},"roleRef":{"kind":"Role","name":"reader"},"subjects":[{"kind":"User","name":"alice"}]}`
const aliceRequest = `[{"id":"alice","username":"alice","groups":[],"verb":"get","apiGroup":"","resource":"pods","namespace":"demo","name":""}]`

func manifest(items ...string) []byte {
	return []byte(`{"apiVersion":"v1","kind":"List","items":[` + strings.Join(items, ",") + `]}`)
}

func TestDefaultingAndBindingResolution(t *testing.T) {
	out := evaluate(manifest(role, binding), []byte(aliceRequest))
	if !out.Valid || len(out.Decisions) != 1 || out.Decisions[0].Decision != "Allow" {
		t.Fatalf("defaulted User/roleRef API groups should produce Allow: %+v", out)
	}
	if !strings.Contains(out.Decisions[0].Reason, `RoleBinding "read/demo"`) {
		t.Fatalf("missing upstream binding attribution: %+v", out.Decisions[0])
	}
	otherNamespace := strings.Replace(aliceRequest, `"namespace":"demo"`, `"namespace":"other"`, 1)
	out = evaluate(manifest(role, binding), []byte(otherNamespace))
	if !out.Valid || len(out.Decisions) != 1 || out.Decisions[0].Decision != "NoOpinion" {
		t.Fatalf("RoleBinding must stay in its namespace: %+v", out)
	}
}

func TestMissingReferenceRemainsVisible(t *testing.T) {
	out := evaluate(manifest(binding), []byte(aliceRequest))
	if !out.Valid || len(out.Decisions) != 1 {
		t.Fatalf("missing references are resolver results, not object validation failures: %+v", out)
	}
	got := out.Decisions[0]
	if got.Decision != "NoOpinion" || !strings.Contains(got.Reason, "role not found") || got.Error != "" {
		t.Fatalf("upstream should return NoOpinion with a resolution reason and nil error: %+v", got)
	}
}

func TestAllowSurvivesOtherMissingReference(t *testing.T) {
	missing := strings.Replace(binding, `"name":"read"`, `"name":"missing-binding"`, 1)
	missing = strings.Replace(missing, `"name":"reader"`, `"name":"missing-role"`, 1)
	out := evaluate(manifest(missing, role, binding), []byte(aliceRequest))
	if !out.Valid || len(out.Decisions) != 1 || out.Decisions[0].Decision != "Allow" || out.Decisions[0].Error != "" {
		t.Fatalf("a matching additive rule still allows after a missing reference: %+v", out)
	}
	if strings.Contains(out.Decisions[0].Reason, "not found") {
		t.Fatalf("production Allow reason replaces prior resolution errors: %+v", out.Decisions[0])
	}
}

func TestServiceAccountBindingNamespaceDefault(t *testing.T) {
	saBinding := strings.Replace(binding, `{"kind":"User","name":"alice"}`, `{"kind":"ServiceAccount","name":"worker"}`, 1)
	saRequest := strings.Replace(aliceRequest, `"username":"alice"`, `"username":"system:serviceaccount:demo:worker"`, 1)
	out := evaluate(manifest(role, saBinding), []byte(saRequest))
	if !out.Valid || len(out.Decisions) != 1 || out.Decisions[0].Decision != "Allow" {
		t.Fatalf("the resolver must default an omitted ServiceAccount namespace to the RoleBinding namespace: %+v", out)
	}
}

func TestNoImplicitAuthenticatedGroup(t *testing.T) {
	groupBinding := strings.Replace(binding, `{"kind":"User","name":"alice"}`, `{"kind":"Group","name":"system:authenticated"}`, 1)
	out := evaluate(manifest(role, groupBinding), []byte(aliceRequest))
	if !out.Valid || len(out.Decisions) != 1 || out.Decisions[0].Decision != "NoOpinion" {
		t.Fatalf("the adapter must not invent authentication groups: %+v", out)
	}
	withGroup := strings.Replace(aliceRequest, `"groups":[]`, `"groups":["system:authenticated"]`, 1)
	out = evaluate(manifest(role, groupBinding), []byte(withGroup))
	if !out.Valid || len(out.Decisions) != 1 || out.Decisions[0].Decision != "Allow" {
		t.Fatalf("explicit authenticated membership should resolve the Group binding: %+v", out)
	}
}

func TestNULInPolicyStringsRemainsLiteral(t *testing.T) {
	for _, change := range []struct {
		field, before, after string
	}{
		{"verbs", `"verbs":["get"]`, `"verbs":["get\u0000suffix"]`},
		{"apiGroups", `"apiGroups":[""]`, `"apiGroups":["\u0000suffix"]`},
		{"resources", `"resources":["pods"]`, `"resources":["pods\u0000suffix"]`},
	} {
		t.Run(change.field, func(t *testing.T) {
			changed := strings.Replace(role, change.before, change.after, 1)
			out := evaluate(manifest(changed, binding), []byte(aliceRequest))
			if !out.Valid || len(out.Decisions) != 1 || out.Decisions[0].Decision != "NoOpinion" {
				t.Fatalf("NUL must not truncate an upstream policy string into a matching prefix: %+v", out)
			}
		})
	}
}

func TestStrictInputAndUpstreamValidation(t *testing.T) {
	cases := []struct {
		name     string
		manifest []byte
		requests string
	}{
		{"unknown object field", manifest(strings.Replace(role, `"rules":`, `"unknown":true,"rules":`, 1)), aliceRequest},
		{"wrong object field type", manifest(strings.Replace(role, `"verbs":["get"]`, `"verbs":true`, 1)), aliceRequest},
		{"duplicate JSON field", manifest(strings.Replace(role, `"verbs":["get"]`, `"verbs":["get"],"verbs":["list"]`, 1)), aliceRequest},
		{"missing role namespace", manifest(strings.Replace(role, `,"namespace":"demo"`, "", 1)), aliceRequest},
		{"invalid binding reference kind", manifest(strings.Replace(binding, `"kind":"Role"`, `"kind":"Secret"`, 1)), aliceRequest},
		{"invalid policy rule", manifest(strings.Replace(role, `"verbs":["get"]`, `"verbs":[]`, 1)), aliceRequest},
		{"duplicate store object", manifest(role, role), aliceRequest},
		{"missing list items", []byte(`{"apiVersion":"v1","kind":"List"}`), aliceRequest},
		{"trailing JSON document", append(manifest(role, binding), []byte(` {"apiVersion":"v1","kind":"List","items":[]}`)...), aliceRequest},
		{"unknown request field", manifest(role, binding), strings.Replace(aliceRequest, `"verb":"get"`, `"verb":"get","extra":1`, 1)},
		{"duplicate request field", manifest(role, binding), strings.Replace(aliceRequest, `"verb":"get"`, `"verb":"get","verb":"list"`, 1)},
		{"missing request field", manifest(role, binding), strings.Replace(aliceRequest, `,"name":""`, "", 1)},
		{"wrong request type", manifest(role, binding), strings.Replace(aliceRequest, `"groups":[]`, `"groups":{}`, 1)},
		{"null request scalar", manifest(role, binding), strings.Replace(aliceRequest, `"name":""`, `"name":null`, 1)},
		{"null group member", manifest(role, binding), strings.Replace(aliceRequest, `"groups":[]`, `"groups":[null]`, 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := evaluate(tc.manifest, []byte(tc.requests))
			if out.Valid || len(out.ValidationErrors) == 0 || len(out.Decisions) != 0 {
				t.Fatalf("invalid input must prevent authorization: %+v", out)
			}
		})
	}
}
