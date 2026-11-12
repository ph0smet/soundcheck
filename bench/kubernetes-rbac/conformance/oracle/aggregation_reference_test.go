package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

func TestAggregationReferenceRunsNestedProductionController(t *testing.T) {
	source := []byte(`{"apiVersion":"v1","kind":"List","items":[
{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"leaf","labels":{"leaf":"yes"}},"rules":[{"verbs":["get"],"apiGroups":[""],"resources":["configmaps"],"resourceNames":["settings"]},{"verbs":["get"],"nonResourceURLs":["/healthz"]}]},
{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"z-middle","labels":{"z-middle":"yes"}},"aggregationRule":{"clusterRoleSelectors":[{"matchLabels":{"leaf":"yes"}}]},"rules":[]},
{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"a-parent","labels":{"z-middle":"yes"}},"aggregationRule":{"clusterRoleSelectors":[{"matchLabels":{"z-middle":"yes"}}]},"rules":[]},
{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"app","namespace":"team-a"},"subjects":[{"kind":"User","apiGroup":"rbac.authorization.k8s.io","name":"app"}],"roleRef":{"kind":"ClusterRole","apiGroup":"rbac.authorization.k8s.io","name":"a-parent"}}
]}`)
	expected := []byte(`{"z-middle":[{"verbs":["get"],"apiGroups":[""],"resources":["configmaps"],"resourceNames":["settings"]},{"verbs":["get"],"nonResourceURLs":["/healthz"]}],"a-parent":[{"verbs":["get"],"apiGroups":[""],"resources":["configmaps"],"resourceNames":["settings"]},{"verbs":["get"],"nonResourceURLs":["/healthz"]}]}`)
	result := runAggregationReference(source, expected)
	if !result.Valid || !result.ControllerExecuted || !result.ExpectedReached || len(result.ValidationErrors) != 0 {
		t.Fatalf("native controller failed: %+v", result)
	}
	if !reflect.DeepEqual(result.AggregateRoles, []string{"a-parent", "z-middle"}) || len(result.Updates) < 2 {
		t.Fatalf("missing production updates: %+v", result)
	}
	if len(result.Reconciliations) < 3 || result.Reconciliations[0] != "a-parent" || result.Reconciliations[1] != "z-middle" || result.Reconciliations[2] != "a-parent" {
		t.Fatalf("parent must run before the child, then be re-enqueued by its update: %v", result.Reconciliations)
	}
	for index, update := range result.Updates {
		if update.ResourceVersion != fmt.Sprint(index+1) {
			t.Fatalf("fake storage did not increment resourceVersion: %+v", result.Updates)
		}
	}
	requests := []byte(`[{"id":"get","username":"app","groups":[],"verb":"get","apiGroup":"","resource":"configmaps","namespace":"team-a","name":"settings"}]`)
	before, after := evaluate(source, requests), evaluate(result.Snapshot, requests)
	if !before.Valid || !after.Valid || before.Decisions[0].Decision != "NoOpinion" || after.Decisions[0].Decision != "Allow" {
		t.Fatalf("native aggregation did not change authorization as expected: before=%+v after=%+v", before, after)
	}
}

func TestAggregationReferenceSelfOnlyBecomesEmpty(t *testing.T) {
	source := []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"self","labels":{"self":"yes"}},"aggregationRule":{"clusterRoleSelectors":[{"matchLabels":{"self":"yes"}}]},"rules":[{"verbs":["*"],"apiGroups":["*"],"resources":["*"]}]}]}`)
	result := runAggregationReference(source, []byte(`{"self":[]}`))
	if !result.Valid || !result.ExpectedReached || len(result.Updates) == 0 {
		t.Fatalf("empty target was not produced by controller: %+v", result)
	}
	objects, failures := decodeManifest(result.Snapshot)
	if len(failures) != 0 || len(objects.clusterRoles) != 1 || len(objects.clusterRoles[0].Rules) != 0 {
		t.Fatalf("self should not supply any rules: %s errors=%v", result.Snapshot, failures)
	}
}

func TestAggregationReferenceNativeValidationPrecedesController(t *testing.T) {
	source := []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"bad"},"aggregationRule":{"clusterRoleSelectors":[]},"rules":[]}]}`)
	result := runAggregationReference(source, []byte(`{"bad":[]}`))
	if result.Valid || result.ControllerExecuted || result.ExpectedReached || len(result.ValidationErrors) == 0 || len(result.Updates) != 0 {
		t.Fatalf("native invalid input reached controller: %+v", result)
	}
}

func TestAggregationReferenceRequiresExactExpectedInventory(t *testing.T) {
	source := []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"root"},"aggregationRule":{"clusterRoleSelectors":[{"matchLabels":{"missing":"yes"}}]},"rules":[]}]}`)
	for _, expected := range []string{`{}`, `{"other":[]}`, `{"root":[],"other":[]}`, `null`, `{"root":[],"root":[]}`} {
		result := runAggregationReference(source, []byte(expected))
		if result.Valid || result.ControllerExecuted || len(result.ValidationErrors) == 0 {
			t.Fatalf("expected inventory %s accepted: %+v", expected, result)
		}
	}
}

func TestAggregationReferenceRuleEqualityKeepsEveryPolicyField(t *testing.T) {
	base := rbacv1.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"settings"}}
	duplicate := *base.DeepCopy()
	duplicate.Verbs = []string{"get", "get"}
	if !reflect.DeepEqual(normalizedAggregationRules([]rbacv1.PolicyRule{base}), normalizedAggregationRules([]rbacv1.PolicyRule{duplicate, base})) {
		t.Fatal("duplicate membership/rules should not change typed rule-set comparison")
	}
	for _, field := range []string{"verbs", "apiGroups", "resources", "resourceNames", "nonResourceURLs"} {
		encoded, _ := json.Marshal(base)
		var fields map[string]interface{}
		_ = json.Unmarshal(encoded, &fields)
		fields[field] = []string{"different"}
		encoded, _ = json.Marshal(fields)
		var changed rbacv1.PolicyRule
		_ = json.Unmarshal(encoded, &changed)
		if reflect.DeepEqual(normalizedAggregationRules([]rbacv1.PolicyRule{base}), normalizedAggregationRules([]rbacv1.PolicyRule{changed})) {
			t.Fatalf("%s change was ignored", field)
		}
	}
}
