package main

import (
	"strings"
	"testing"
)

func TestPolicyComparisonIgnoresBookkeepingButRetainsPolicy(t *testing.T) {
	prepared := manifest(role, binding)
	withMetadata := strings.Replace(string(prepared), `"name":"reader","namespace":"demo"`,
		`"name":"reader","namespace":"demo","uid":"2f4f9284-9e8f-4ed8-9003-d20b515839bb","resourceVersion":"123","generation":4,"creationTimestamp":"2026-11-08T00:00:00Z"`, 1)
	out := comparePolicies([]byte(withMetadata), prepared)
	if !out.Valid || out.PolicyEqual == nil || !*out.PolicyEqual || len(out.Differences) != 0 {
		t.Fatalf("bookkeeping must not change typed policy: %+v", out)
	}
	if out.OriginalSHA256 == out.PreparedSHA256 || *out.OriginalPolicySHA256 != *out.PreparedPolicySHA256 || *out.OriginalObjects != 2 {
		t.Fatalf("exact source hashes and typed-policy hashes must be distinguished: %+v", out)
	}
	// Object ordering can change without adding or deleting a policy object.
	out = comparePolicies(prepared, manifest(binding, role))
	if !out.Valid || out.PolicyEqual == nil || !*out.PolicyEqual {
		t.Fatalf("inventory equality is independent of object ordering: %+v", out)
	}
}

func TestPolicyComparisonDetectsDroppedOrChangedAuthorizationFields(t *testing.T) {
	baseRole := strings.Replace(role, `"resources":["pods"]`, `"resources":["pods"],"resourceNames":["one"]`, 1)
	original := manifest(baseRole, binding)
	cases := map[string][]byte{
		"binding dropped":          manifest(baseRole),
		"name restriction widened": manifest(role, binding),
		"subject changed":          manifest(baseRole, strings.Replace(binding, `"name":"alice"`, `"name":"bob"`, 1)),
		"namespace changed":        manifest(strings.Replace(baseRole, `"namespace":"demo"`, `"namespace":"other"`, 1), binding),
		"verb changed":             manifest(strings.Replace(baseRole, `"verbs":["get"]`, `"verbs":["list"]`, 1), binding),
		"reference changed":        manifest(baseRole, strings.Replace(binding, `"name":"reader"`, `"name":"missing"`, 1)),
		"annotation erased":        manifest(baseRole, binding),
	}
	for name, prepared := range cases {
		source := original
		if name == "annotation erased" {
			source = []byte(strings.Replace(string(original), `"name":"reader","namespace":"demo"`,
				`"name":"reader","namespace":"demo","annotations":{"reviewed":"true"}`, 1))
		}
		out := comparePolicies(source, prepared)
		if !out.Valid || out.PolicyEqual == nil || *out.PolicyEqual || len(out.Differences) == 0 {
			t.Fatalf("%s must differ even when a finite request matrix could miss it: %+v", name, out)
		}
	}
}

func TestPolicyComparisonDefaultsBothOriginalAndPreparedIndependently(t *testing.T) {
	explicit := strings.Replace(binding, `"roleRef":{"kind"`, `"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind"`, 1)
	explicit = strings.Replace(explicit, `"subjects":[{"kind"`, `"subjects":[{"apiGroup":"rbac.authorization.k8s.io","kind"`, 1)
	out := comparePolicies(manifest(role, binding), manifest(role, explicit))
	if !out.Valid || out.PolicyEqual == nil || !*out.PolicyEqual {
		t.Fatalf("upstream defaulting must be applied to each original input: %+v", out)
	}
}

func TestPolicyComparisonCannotLaunderInvalidOriginal(t *testing.T) {
	prepared := manifest(role, binding)
	for _, original := range [][]byte{
		[]byte(strings.Replace(string(prepared), `"name":"reader","namespace":"demo"`,
			`"name":"reader","namespace":"demo","generation":-1`, 1)),
		[]byte(strings.Replace(string(prepared), `"name":"reader","namespace":"demo"`,
			`"name":"reader","namespace":"demo","resourceVersion":123`, 1)),
		[]byte(strings.Replace(string(prepared), `"verbs":["get"]`, `"verbs":["get"],"verbs":["list"]`, 1)),
		manifest(role, role, binding),
	} {
		out := comparePolicies(original, prepared)
		if out.Valid || out.PolicyEqual != nil || len(out.ValidationErrors) == 0 || out.OriginalPolicySHA256 != nil {
			t.Fatalf("invalid original must fail before comparison: %+v", out)
		}
	}
}
