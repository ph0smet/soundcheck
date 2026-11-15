package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func sequenceTestContract(single []byte) []byte {
	var value map[string]interface{}
	if err := json.Unmarshal(single, &value); err != nil {
		panic(err)
	}
	value["kind"] = "kubernetes-rbac-policy-sequence"
	value["steps"] = []interface{}{map[string]interface{}{"operation": value["operation"], "target": value["target"]}}
	delete(value, "operation")
	delete(value, "target")
	return changeTestBytes(value)
}

func TestPolicySequenceOneStepMatchesNativeGuard(t *testing.T) {
	for _, kind := range []string{"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"} {
		for _, operation := range []string{"create", "update-existing"} {
			for _, mode := range []string{"covered", "explicit", "ungranted"} {
				t.Run(kind+"/"+operation+"/"+mode, func(t *testing.T) {
					before, after, single := changeTestFixture(kind, operation, mode == "covered", mode != "ungranted", mode == "explicit")
					want := evaluatePolicyChange(before, after, single)
					got := evaluatePolicySequence(before, after, sequenceTestContract(single))
					if !got.Valid || len(got.Steps) != 1 || !reflect.DeepEqual(got.Steps[0].Native, want) || got.Accepted != want.Accepted {
						t.Fatalf("one-step sequence did not retain native stage decisions: %#v / %#v", got, want)
					}
					if got.StateCount != 2 || string(got.States[0]) != string(before) || string(got.States[1]) != string(after) {
						t.Fatal("endpoint bytes changed")
					}
				})
			}
		}
	}
}

func TestPolicySequenceWholePlanPrecedesAuthorization(t *testing.T) {
	before, after, single := changeTestFixture("Role", "create", false, false, false)
	var spec map[string]interface{}
	json.Unmarshal(sequenceTestContract(single), &spec)
	steps := spec["steps"].([]interface{})
	for _, mutation := range []string{"zero", "duplicate", "over-limit", "unknown-operation", "unknown-step-field", "missing-namespace"} {
		t.Run(mutation, func(t *testing.T) {
			var changed map[string]interface{}
			json.Unmarshal(changeTestBytes(spec), &changed)
			items := changed["steps"].([]interface{})
			switch mutation {
			case "zero":
				changed["steps"] = []interface{}{}
			case "duplicate":
				changed["steps"] = append(items, steps[0])
			case "over-limit":
				changed["steps"] = make([]interface{}, 17)
			case "unknown-operation":
				items[0].(map[string]interface{})["operation"] = "patch"
			case "unknown-step-field":
				items[0].(map[string]interface{})["actor"] = "untrusted"
			case "missing-namespace":
				delete(items[0].(map[string]interface{})["target"].(map[string]interface{}), "namespace")
			}
			got := evaluatePolicySequence(before, after, changeTestBytes(changed))
			if got.Valid || got.Accepted || len(got.Steps) != 0 || len(got.States) != 0 || len(got.ValidationErrors) == 0 {
				t.Fatalf("unsupported plan reached authorization: %#v", got)
			}
		})
	}
}

func TestPolicySequenceRejectsForwardRoleReference(t *testing.T) {
	before, after, single := changeTestFixture("RoleBinding", "create", false, true, true)
	var baseline, final map[string]interface{}
	json.Unmarshal(before, &baseline)
	json.Unmarshal(after, &final)
	var spec map[string]interface{}
	json.Unmarshal(sequenceTestContract(single), &spec)
	// Remove the referenced role from the baseline and declare its creation as
	// a later step. The final inventory is complete; the first prefix is not.
	items := baseline["items"].([]interface{})
	filtered := []interface{}{}
	var target map[string]interface{}
	for _, item := range items {
		obj := item.(map[string]interface{})
		if obj["kind"] == "ClusterRole" && obj["metadata"].(map[string]interface{})["name"] == "referenced" {
			target = map[string]interface{}{"kind": "ClusterRole", "namespace": nil, "name": "referenced"}
		} else {
			filtered = append(filtered, item)
		}
	}
	if target == nil {
		t.Fatal("fixture referenced role changed")
	}
	baseline["items"] = filtered
	spec["steps"] = append(spec["steps"].([]interface{}), map[string]interface{}{"operation": "create", "target": target})
	got := evaluatePolicySequence(changeTestBytes(baseline), after, changeTestBytes(spec))
	if got.Valid || len(got.Steps) != 0 || len(got.ValidationErrors) == 0 {
		t.Fatalf("forward reference reached a native guard: %#v", got)
	}
}
