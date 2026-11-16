package main

import (
	"encoding/json"
	"testing"
)

func retirementTestFixture(kind, grantedName string) ([]byte, []byte, []byte) {
	_, after, contract := changeTestFixture(kind, "create", false, false, false)
	var baseline, spec map[string]interface{}
	json.Unmarshal(after, &baseline)
	json.Unmarshal(contract, &spec)
	resources := map[string]string{"Role": "roles", "ClusterRole": "clusterroles", "RoleBinding": "rolebindings", "ClusterRoleBinding": "clusterrolebindings"}
	items := baseline["items"].([]interface{})
	items[0].(map[string]interface{})["rules"] = []interface{}{map[string]interface{}{
		"apiGroups": []string{"rbac.authorization.k8s.io"}, "resources": []string{resources[kind]},
		"verbs": []string{"delete"}, "resourceNames": []string{grantedName}}}
	final := map[string]interface{}{"apiVersion": "v1", "kind": "List", "items": items[:len(items)-1]}
	spec["schema_version"], spec["operation"] = 2, "delete-existing"
	return changeTestBytes(baseline), changeTestBytes(final), changeTestBytes(spec)
}

func TestPolicyRetirementNativeDeleteUsesInitialNamedAuthorityOnly(t *testing.T) {
	for _, kind := range []string{"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"} {
		for _, name := range []string{"target", "another-target", ""} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				before, after, contract := retirementTestFixture(kind, name)
				result := evaluatePolicyChange(before, after, contract)
				allowed := name == "target"
				if !result.Valid || result.Accepted != allowed || result.GuardAccepted != allowed || result.StorageCalls != map[bool]int{false: 0, true: 1}[allowed] {
					t.Fatalf("wrong ordinary deletion result: %s", changeTestBytes(result))
				}
				if result.Initial == nil || result.Initial.Attributes.Verb != "delete" || result.Initial.Attributes.Name != "target" ||
					result.Initial.Attributes.APIVersion != "v1" || len(result.Special) != 0 || len(result.Resolutions) != 0 || len(result.Coverage) != 0 {
					t.Fatalf("deletion ran creation/update policy guards: %s", changeTestBytes(result))
				}
				sequence := map[string]interface{}{}
				json.Unmarshal(sequenceTestContract(contract), &sequence)
				sequence["invariants"] = []string{}
				composed := evaluatePolicySequence(before, after, changeTestBytes(sequence))
				if !composed.Valid || composed.Accepted != allowed || len(composed.Steps) != 1 || composed.StateCount != 2 {
					t.Fatalf("one deletion sequence disagrees: %s", changeTestBytes(composed))
				}
			})
		}
	}
}

func TestPolicyRetirementRejectsAbsentRetainedAndDeferredTargets(t *testing.T) {
	for _, mutation := range []string{"absent", "retained", "finalizers", "ownerReferences", "deletionTimestamp", "schema1", "delete-options"} {
		t.Run(mutation, func(t *testing.T) {
			before, after, contract := retirementTestFixture("Role", "target")
			var baseline, final, spec map[string]interface{}
			json.Unmarshal(before, &baseline)
			json.Unmarshal(after, &final)
			json.Unmarshal(contract, &spec)
			items := baseline["items"].([]interface{})
			switch mutation {
			case "absent":
				baseline["items"] = items[:len(items)-1]
			case "retained":
				final = baseline
			case "schema1":
				spec["schema_version"] = 1
			case "delete-options":
				spec["delete_options"] = map[string]interface{}{"propagationPolicy": "Foreground"}
			default:
				items[len(items)-1].(map[string]interface{})["metadata"].(map[string]interface{})[mutation] = nil
			}
			got := evaluatePolicyChange(changeTestBytes(baseline), changeTestBytes(final), changeTestBytes(spec))
			if got.Valid || got.Initial != nil || got.Accepted || got.StorageCalls != 0 {
				t.Fatalf("boundary reached native deletion: %s", changeTestBytes(got))
			}
		})
	}
}

func TestPolicyRetirementInvariantSelectionIsFrozen(t *testing.T) {
	before, after, single := retirementTestFixture("Role", "target")
	var spec map[string]interface{}
	json.Unmarshal(sequenceTestContract(single), &spec)
	spec["requirements"].(map[string]interface{})["clauses"] = []interface{}{map[string]interface{}{"name": "keep-access"}}
	for _, mutation := range []string{"missing", "null", "unknown", "duplicate", "wrong-type", "schema1"} {
		t.Run(mutation, func(t *testing.T) {
			var changed map[string]interface{}
			json.Unmarshal(changeTestBytes(spec), &changed)
			switch mutation {
			case "missing":
			case "null":
				changed["invariants"] = nil
			case "unknown":
				changed["invariants"] = []string{"absent"}
			case "duplicate":
				changed["invariants"] = []string{"keep-access", "keep-access"}
			case "wrong-type":
				changed["invariants"] = []int{1}
			case "schema1":
				changed["schema_version"] = 1
				changed["invariants"] = []string{}
			}
			got := evaluatePolicySequence(before, after, changeTestBytes(changed))
			if got.Valid || got.Accepted || len(got.Steps) != 0 {
				t.Fatalf("invalid invariant selection reached native guards: %s", changeTestBytes(got))
			}
		})
	}
}
