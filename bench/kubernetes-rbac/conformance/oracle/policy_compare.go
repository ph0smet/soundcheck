package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"
)

// This projection uses upstream typed objects after upstream defaulting and
// validation. It is independent of Soundcheck's parser and preparation code.
// Keep all authorization fields, even features outside Soundcheck's profile,
// and labels/annotations. Object order is irrelevant; rule/subject order and
// individual names remain intact. Lifecycle/bookkeeping metadata is not an
// authorization input to the pinned DefaultRuleResolver/RBACAuthorizer.
type policyObject struct {
	Kind            string                  `json:"kind"`
	Namespace       string                  `json:"namespace"`
	Name            string                  `json:"name"`
	Labels          map[string]string       `json:"labels"`
	Annotations     map[string]string       `json:"annotations"`
	Rules           []rbacv1.PolicyRule     `json:"rules"`
	Subjects        []rbacv1.Subject        `json:"subjects"`
	RoleRef         *rbacv1.RoleRef         `json:"roleRef"`
	AggregationRule *rbacv1.AggregationRule `json:"aggregationRule"`
}

type policyComparison struct {
	SchemaVersion        int      `json:"schema_version"`
	Kind                 string   `json:"kind"`
	Valid                bool     `json:"valid"`
	OriginalSHA256       string   `json:"original_sha256"`
	PreparedSHA256       string   `json:"prepared_sha256"`
	PolicyEqual          *bool    `json:"policy_equal"`
	OriginalPolicySHA256 *string  `json:"original_policy_sha256"`
	PreparedPolicySHA256 *string  `json:"prepared_policy_sha256"`
	OriginalObjects      *int     `json:"original_objects"`
	PreparedObjects      *int     `json:"prepared_objects"`
	ValidationErrors     []string `json:"validation_errors"`
	Differences          []string `json:"differences"`
}

func sha256Text(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func emptyPolicyComparison() policyComparison {
	return policyComparison{SchemaVersion: 1, Kind: "typed_rbac_policy_comparison",
		ValidationErrors: []string{}, Differences: []string{}}
}

func projectPolicies(objects inventory) map[string]policyObject {
	out := map[string]policyObject{}
	add := func(obj policyObject) {
		out[obj.Kind+"\x00"+obj.Namespace+"\x00"+obj.Name] = obj
	}
	for _, role := range objects.roles {
		add(policyObject{Kind: "Role", Namespace: role.Namespace, Name: role.Name,
			Labels: role.Labels, Annotations: role.Annotations, Rules: role.Rules})
	}
	for _, role := range objects.clusterRoles {
		add(policyObject{Kind: "ClusterRole", Name: role.Name,
			Labels: role.Labels, Annotations: role.Annotations,
			Rules: role.Rules, AggregationRule: role.AggregationRule})
	}
	for _, binding := range objects.roleBindings {
		add(policyObject{Kind: "RoleBinding", Namespace: binding.Namespace, Name: binding.Name,
			Labels: binding.Labels, Annotations: binding.Annotations,
			Subjects: binding.Subjects, RoleRef: &binding.RoleRef})
	}
	for _, binding := range objects.clusterRoleBindings {
		add(policyObject{Kind: "ClusterRoleBinding", Name: binding.Name,
			Labels: binding.Labels, Annotations: binding.Annotations,
			Subjects: binding.Subjects, RoleRef: &binding.RoleRef})
	}
	return out
}

func comparePolicies(original, prepared []byte) policyComparison {
	out := emptyPolicyComparison()
	out.OriginalSHA256, out.PreparedSHA256 = sha256Text(original), sha256Text(prepared)
	before, beforeErrors := decodeManifest(original)
	after, afterErrors := decodeManifest(prepared)
	for _, err := range beforeErrors {
		out.ValidationErrors = append(out.ValidationErrors, "original: "+err)
	}
	for _, err := range afterErrors {
		out.ValidationErrors = append(out.ValidationErrors, "prepared: "+err)
	}
	if len(out.ValidationErrors) != 0 {
		return out
	}
	out.Valid = true
	left, right := projectPolicies(before), projectPolicies(after)
	leftBytes, leftError := json.Marshal(left)
	rightBytes, rightError := json.Marshal(right)
	if leftError != nil || rightError != nil {
		panic("validated typed policy cannot be serialized")
	}
	leftHash, rightHash := sha256Text(leftBytes), sha256Text(rightBytes)
	leftCount, rightCount := len(left), len(right)
	out.OriginalPolicySHA256, out.PreparedPolicySHA256 = &leftHash, &rightHash
	out.OriginalObjects, out.PreparedObjects = &leftCount, &rightCount
	for key, value := range left {
		if other, exists := right[key]; !exists {
			out.Differences = append(out.Differences, "removed: "+key)
		} else if !reflect.DeepEqual(value, other) {
			out.Differences = append(out.Differences, "changed: "+key)
		}
	}
	for key := range right {
		if _, exists := left[key]; !exists {
			out.Differences = append(out.Differences, "added: "+key)
		}
	}
	sort.Strings(out.Differences)
	equal := len(out.Differences) == 0
	out.PolicyEqual = &equal
	return out
}

func comparePolicyFiles(paths []string) {
	out := emptyPolicyComparison()
	status := 2
	if len(paths) != 2 {
		out.ValidationErrors = append(out.ValidationErrors, "usage: rbac-oracle --compare-policies ORIGINAL.json PREPARED.json")
	} else {
		original, originalError := os.ReadFile(paths[0])
		prepared, preparedError := os.ReadFile(paths[1])
		if originalError != nil {
			out.ValidationErrors = append(out.ValidationErrors, "original: "+originalError.Error())
		}
		if preparedError != nil {
			out.ValidationErrors = append(out.ValidationErrors, "prepared: "+preparedError.Error())
		}
		if len(out.ValidationErrors) == 0 {
			out = comparePolicies(original, prepared)
			status = 1
			if out.Valid && out.PolicyEqual != nil && *out.PolicyEqual {
				status = 0
			}
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(status)
}
