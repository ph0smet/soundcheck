package main

// The sequence adapter constructs its own complete policy states and executes
// the native single-write guards in order. It never consumes production state
// artifacts or Soundcheck authorization decisions.
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	rbacresolver "k8s.io/kubernetes/pkg/registry/rbac/validation"
	strictjson "sigs.k8s.io/json"
)

type policySequenceStep struct {
	Operation string             `json:"operation"`
	Target    policyChangeTarget `json:"target"`
}

type policySequenceSpec struct {
	SchemaVersion int                  `json:"schema_version"`
	Kind          string               `json:"kind"`
	Actor         string               `json:"actor"`
	Steps         []policySequenceStep `json:"steps"`
	Requirements  json.RawMessage      `json:"requirements"`
}

type policySequenceExecution struct {
	Index        int                `json:"index"`
	BeforeSHA256 string             `json:"before_sha256"`
	AfterSHA256  string             `json:"after_sha256"`
	Native       policyChangeResult `json:"native"`
}

type policySequenceResult struct {
	SchemaVersion    int                       `json:"schema_version"`
	Kind             string                    `json:"kind"`
	Valid            bool                      `json:"valid"`
	ValidationErrors []string                  `json:"validation_errors"`
	Accepted         bool                      `json:"accepted"`
	FailedStep       *int                      `json:"failed_step"`
	StateCount       int                       `json:"state_count"`
	States           []json.RawMessage         `json:"states"`
	Steps            []policySequenceExecution `json:"steps"`
}

func emptyPolicySequenceResult() policySequenceResult {
	return policySequenceResult{SchemaVersion: 1, Kind: "rbac_policy_sequence_native",
		ValidationErrors: []string{}, States: []json.RawMessage{}, Steps: []policySequenceExecution{}}
}

func policySequenceKey(target policyChangeTarget) string {
	return target.Kind + "\x00" + target.Namespace + "\x00" + target.Name
}

func policySequenceSingle(spec policySequenceSpec, step policySequenceStep) []byte {
	var namespace interface{}
	if step.Target.Namespace != "" {
		namespace = step.Target.Namespace
	}
	data, err := json.Marshal(map[string]interface{}{
		"schema_version": 1, "kind": "kubernetes-rbac-policy-change", "actor": spec.Actor,
		"operation": step.Operation, "requirements": spec.Requirements,
		"target": map[string]interface{}{"kind": step.Target.Kind, "namespace": namespace, "name": step.Target.Name}})
	if err != nil {
		panic(err)
	}
	return data
}

func decodePolicySequenceSpec(data []byte) (policySequenceSpec, error) {
	var spec policySequenceSpec
	strictErrors, err := strictjson.UnmarshalStrict(data, &spec)
	if err != nil || len(strictErrors) != 0 {
		return spec, fmt.Errorf("invalid sequence contract: %v %v", err, strictErrors)
	}
	if spec.SchemaVersion != 1 || spec.Kind != "kubernetes-rbac-policy-sequence" || len(spec.Steps) < 1 || len(spec.Steps) > 16 {
		return spec, fmt.Errorf("expected sequence schema 1 with 1..16 steps")
	}
	var raw struct {
		Steps []json.RawMessage `json:"steps"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return spec, err
	}
	seen := map[string]bool{}
	for index, step := range spec.Steps {
		var rawStep map[string]json.RawMessage
		if err := json.Unmarshal(raw.Steps[index], &rawStep); err != nil || len(rawStep) != 2 {
			return spec, fmt.Errorf("step %d requires operation and target", index+1)
		}
		// Preserve raw namespace null/string representation for the single-write
		// decoder, rather than silently normalizing malformed target fields.
		value := map[string]interface{}{"schema_version": 1, "kind": "kubernetes-rbac-policy-change",
			"actor": spec.Actor, "operation": step.Operation, "target": rawStep["target"], "requirements": spec.Requirements}
		encoded, _ := json.Marshal(value)
		if _, _, err := decodePolicyChangeSpec(encoded); err != nil {
			return spec, fmt.Errorf("step %d: %w", index+1, err)
		}
		key := policySequenceKey(step.Target)
		if seen[key] {
			return spec, fmt.Errorf("duplicate target at step %d", index+1)
		}
		seen[key] = true
	}
	return spec, nil
}

// Complete snapshots resolve every binding, not only bindings for the caller.
// Aggregate consistency is independently checked by the native controller.
// Native selectors are also used to reject cyclic aggregate dependencies,
// which are outside the approved static inventory boundary.
func policySequenceInventory(data []byte) (inventory, error) {
	objects, failures := decodeManifest(data)
	if len(failures) != 0 {
		return objects, fmt.Errorf("invalid inventory: %v", failures)
	}
	resolver, _ := rbacresolver.NewTestRuleResolver(objects.roles, objects.roleBindings, objects.clusterRoles, objects.clusterRoleBindings)
	for _, binding := range objects.roleBindings {
		if _, err := resolver.GetRoleReferenceRules(context.Background(), binding.RoleRef, binding.Namespace); err != nil {
			return objects, fmt.Errorf("incomplete binding %s/%s: %w", binding.Namespace, binding.Name, err)
		}
	}
	for _, binding := range objects.clusterRoleBindings {
		if _, err := resolver.GetRoleReferenceRules(context.Background(), binding.RoleRef, ""); err != nil {
			return objects, fmt.Errorf("incomplete binding %s: %w", binding.Name, err)
		}
	}
	expected := map[string][]rbacv1.PolicyRule{}
	edges := map[string][]string{}
	for _, role := range objects.clusterRoles {
		if role.AggregationRule == nil {
			continue
		}
		expected[role.Name] = policyChangeRules(role.Rules)
		for _, selector := range role.AggregationRule.ClusterRoleSelectors {
			match, err := metav1.LabelSelectorAsSelector(&selector)
			if err != nil {
				return objects, err
			}
			for _, candidate := range objects.clusterRoles {
				if candidate.Name != role.Name && candidate.AggregationRule != nil && match.Matches(labels.Set(candidate.Labels)) {
					edges[role.Name] = append(edges[role.Name], candidate.Name)
				}
			}
		}
	}
	marks := map[string]int{}
	var visit func(string) bool
	visit = func(name string) bool {
		if marks[name] == 1 {
			return false
		}
		if marks[name] == 2 {
			return true
		}
		marks[name] = 1
		for _, next := range edges[name] {
			if !visit(next) {
				return false
			}
		}
		marks[name] = 2
		return true
	}
	for name := range expected {
		if !visit(name) {
			return objects, fmt.Errorf("cyclic aggregate dependency")
		}
	}
	if len(expected) != 0 {
		encoded, _ := json.Marshal(expected)
		check := runAggregationReference(data, encoded)
		if !check.Valid || !check.ExpectedReached {
			return objects, fmt.Errorf("aggregate snapshot is not the native controller fixed point: %v", check.ValidationErrors)
		}
	}
	return objects, nil
}

// Replace in the reference's own List, retaining existing order and appending
// newly created objects. Each value is copied from the final input only once.
func policySequenceInstall(current []byte, target policyChangeTarget, replacement []byte) ([]byte, error) {
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(current, &list); err != nil {
		return nil, err
	}
	found := false
	for index, raw := range list.Items {
		objects, err := policyChangeRawObjects(append(append([]byte(`{"items":[`), raw...), []byte(`]}`)...))
		if err != nil {
			return nil, err
		}
		if _, ok := objects[policySequenceKey(target)]; ok {
			list.Items[index] = append(json.RawMessage{}, replacement...)
			found = true
		}
	}
	if !found {
		list.Items = append(list.Items, append(json.RawMessage{}, replacement...))
	}
	return json.Marshal(map[string]interface{}{"apiVersion": "v1", "kind": "List", "items": list.Items})
}

func policySequencePlan(before, after, contract []byte) (policySequenceSpec, []json.RawMessage, error) {
	spec, err := decodePolicySequenceSpec(contract)
	if err != nil {
		return spec, nil, err
	}
	left, err := policyChangeRawObjects(before)
	if err != nil {
		return spec, nil, err
	}
	right, err := policyChangeRawObjects(after)
	if err != nil {
		return spec, nil, err
	}
	targets := map[string]bool{}
	for _, step := range spec.Steps {
		targets[policySequenceKey(step.Target)] = true
	}
	for key, value := range left {
		if !targets[key] && !bytes.Equal(value, right[key]) {
			return spec, nil, fmt.Errorf("untargeted object changed: %q", key)
		}
	}
	for key := range right {
		if _, exists := left[key]; !exists && !targets[key] {
			return spec, nil, fmt.Errorf("untargeted object added: %q", key)
		}
	}
	previous, err := policySequenceInventory(before)
	if err != nil {
		return spec, nil, fmt.Errorf("state 0: %w", err)
	}
	if _, err := policySequenceInventory(after); err != nil {
		return spec, nil, fmt.Errorf("final inventory: %w", err)
	}
	states := []json.RawMessage{append(json.RawMessage{}, before...)}
	for index, step := range spec.Steps {
		replacement, exists := right[policySequenceKey(step.Target)]
		if !exists {
			return spec, nil, fmt.Errorf("step %d target is absent from final inventory", index+1)
		}
		next, err := policySequenceInstall(states[len(states)-1], step.Target, replacement)
		if err != nil {
			return spec, nil, err
		}
		objects, err := policySequenceInventory(next)
		if err != nil {
			return spec, nil, fmt.Errorf("state %d: %w", index+1, err)
		}
		single, _, err := decodePolicyChangeSpec(policySequenceSingle(spec, step))
		if err == nil {
			err = policyChangeBoundary(states[len(states)-1], next, previous, objects, single)
		}
		if err != nil {
			return spec, nil, fmt.Errorf("step %d: %w", index+1, err)
		}
		states = append(states, next)
		previous = objects
	}
	// The last input is the exact submitted final snapshot. Its item order is
	// irrelevant to the operation order, but its byte identity remains binding.
	states[len(states)-1] = append(json.RawMessage{}, after...)
	return spec, states, nil
}

func evaluatePolicySequence(before, after, contract []byte) policySequenceResult {
	out := emptyPolicySequenceResult()
	spec, planned, err := policySequencePlan(before, after, contract)
	if err != nil {
		out.ValidationErrors = append(out.ValidationErrors, err.Error())
		return out
	}
	out.Valid = true
	out.States = planned
	out.StateCount = len(planned)
	current := planned[0]
	for index, step := range spec.Steps {
		// evaluatePolicyChange builds a new native rule resolver from current,
		// calls the real request filters, RBAC and policybased storage wrapper.
		next := planned[index+1]
		entry := evaluatePolicyChange(current, next, policySequenceSingle(spec, step))
		out.Steps = append(out.Steps, policySequenceExecution{Index: index + 1,
			BeforeSHA256: sha256Text(current), AfterSHA256: sha256Text(next), Native: entry})
		if !entry.Valid || !entry.Accepted {
			failed := index + 1
			out.FailedStep = &failed
			return out
		}
		// Advance only after the real native guard and terminal strategy
		// accepted. This is fixture persistence, not a live-cluster claim.
		current = next
	}
	out.Accepted = true
	return out
}

func policySequenceReferenceFiles(paths []string) {
	out := emptyPolicySequenceResult()
	code := 2
	if len(paths) != 3 {
		out.ValidationErrors = append(out.ValidationErrors, "usage: --policy-sequence-reference BEFORE AFTER CONTRACT")
	} else {
		data := make([][]byte, 3)
		for index, path := range paths {
			var err error
			data[index], err = os.ReadFile(path)
			if err != nil {
				out.ValidationErrors = append(out.ValidationErrors, err.Error())
			}
		}
		if len(out.ValidationErrors) == 0 {
			out = evaluatePolicySequence(data[0], data[1], data[2])
			code = 1
			if out.Valid {
				code = 0
			}
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(code)
}
