// Soundcheck's in-memory reference adapter to Kubernetes v1.34.0 RBAC.
// Kubernetes implementation code is imported from the pinned upstream modules,
// under Apache-2.0 (see KUBERNETES-LICENSE); it is not reimplemented here.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	rbacinternal "k8s.io/kubernetes/pkg/apis/rbac"
	rbacv1scheme "k8s.io/kubernetes/pkg/apis/rbac/v1"
	rbacvalidation "k8s.io/kubernetes/pkg/apis/rbac/validation"
	rbacresolver "k8s.io/kubernetes/pkg/registry/rbac/validation"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
	strictjson "sigs.k8s.io/json"
)

type request struct {
	ID              string   `json:"id"`
	Username        string   `json:"username"`
	Groups          []string `json:"groups"`
	Verb            string   `json:"verb"`
	APIGroup        string   `json:"apiGroup"`
	Resource        string   `json:"resource"`
	Namespace       string   `json:"namespace"`
	Name            string   `json:"name"`
	Subresource     string   `json:"subresource,omitempty"`
	ResourceRequest *bool    `json:"resourceRequest,omitempty"`
	Path            string   `json:"path,omitempty"`
}

type decision struct {
	ID       string `json:"id"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	Error    string `json:"error"`
}

type result struct {
	Valid            bool       `json:"valid"`
	ValidationErrors []string   `json:"validation_errors"`
	Decisions        []decision `json:"decisions"`
}

type inventory struct {
	roles               []*rbacv1.Role
	roleBindings        []*rbacv1.RoleBinding
	clusterRoles        []*rbacv1.ClusterRole
	clusterRoleBindings []*rbacv1.ClusterRoleBinding
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--manifest-reference" {
		manifestReferenceFiles(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--request-urls" {
		requestURLFiles(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--compare-policies" {
		comparePolicyFiles(os.Args[2:])
		return
	}
	out := emptyResult()
	if len(os.Args) != 3 {
		out.ValidationErrors = append(out.ValidationErrors, "usage: rbac-oracle MANIFEST.json REQUESTS.json")
		emit(out, 2)
		return
	}
	manifest, err := os.ReadFile(os.Args[1])
	if err != nil {
		out.ValidationErrors = append(out.ValidationErrors, "manifest: "+err.Error())
	}
	requests, err := os.ReadFile(os.Args[2])
	if err != nil {
		out.ValidationErrors = append(out.ValidationErrors, "requests: "+err.Error())
	}
	if len(out.ValidationErrors) > 0 {
		emit(out, 2)
		return
	}
	out = evaluate(manifest, requests)
	if !out.Valid {
		emit(out, 1)
		return
	}
	emit(out, 0)
}

func emptyResult() result {
	return result{ValidationErrors: []string{}, Decisions: []decision{}}
}

func emit(out result, exitCode int) {
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(exitCode)
}

func evaluate(manifestJSON, requestsJSON []byte) result {
	out := emptyResult()
	objects, manifestErrors := decodeManifest(manifestJSON)
	requests, requestErrors := decodeRequests(requestsJSON)
	out.ValidationErrors = append(out.ValidationErrors, manifestErrors...)
	out.ValidationErrors = append(out.ValidationErrors, requestErrors...)
	if len(out.ValidationErrors) > 0 {
		return out
	}

	// StaticRoles supplies only in-memory storage. New builds the production
	// DefaultRuleResolver, including subject matching and binding resolution.
	_, static := rbacresolver.NewTestRuleResolver(objects.roles, objects.roleBindings,
		objects.clusterRoles, objects.clusterRoleBindings)
	rbac := rbacauthorizer.New(static, static, static, static)
	out.Valid = true
	for _, req := range requests {
		isResource := true
		if req.ResourceRequest != nil {
			isResource = *req.ResourceRequest
		}
		attributes := authorizer.AttributesRecord{
			User:            &user.DefaultInfo{Name: req.Username, Groups: req.Groups},
			Verb:            req.Verb,
			APIGroup:        req.APIGroup,
			Resource:        req.Resource,
			Namespace:       req.Namespace,
			Name:            req.Name,
			Subresource:     req.Subresource,
			ResourceRequest: isResource,
			Path:            req.Path,
		}
		verdict, reason, err := rbac.Authorize(context.Background(), attributes)
		item := decision{ID: req.ID, Reason: reason}
		switch verdict {
		case authorizer.DecisionAllow:
			item.Decision = "Allow"
		case authorizer.DecisionNoOpinion:
			item.Decision = "NoOpinion"
		case authorizer.DecisionDeny:
			item.Decision = "Deny"
		default:
			panic(fmt.Sprintf("unexpected upstream authorizer decision: %v", verdict))
		}
		if err != nil {
			item.Error = err.Error()
		}
		out.Decisions = append(out.Decisions, item)
	}
	return out
}

func decodeManifest(data []byte) (inventory, []string) {
	objects := inventory{}
	errors := []string{}
	if !json.Valid(data) {
		return objects, []string{"manifest: expected one valid JSON document"}
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, rbacinternal.AddToScheme, rbacv1scheme.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			return objects, []string{"scheme: " + err.Error()}
		}
	}
	decoder := serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDeserializer()
	obj, gvk, err := decoder.Decode(data, nil, nil)
	if err != nil {
		return objects, []string{"manifest: " + err.Error()}
	}
	list, ok := obj.(*corev1.List)
	if !ok || gvk == nil || gvk.GroupVersion() != corev1.SchemeGroupVersion || gvk.Kind != "List" {
		return objects, []string{"manifest: expected apiVersion v1 and kind List"}
	}
	if list.Items == nil {
		return objects, []string{"manifest.items: expected an array (use [] for an empty snapshot)"}
	}
	seen := map[string]int{}
	for index, raw := range list.Items {
		prefix := fmt.Sprintf("manifest.items[%d]", index)
		obj, gvk, err := decoder.Decode(raw.Raw, nil, nil)
		if err != nil {
			errors = append(errors, prefix+": "+err.Error())
			continue
		}
		if gvk == nil || gvk.GroupVersion() != rbacv1.SchemeGroupVersion {
			errors = append(errors, prefix+": expected rbac.authorization.k8s.io/v1")
			continue
		}
		switch obj.(type) {
		case *rbacv1.Role, *rbacv1.ClusterRole, *rbacv1.RoleBinding, *rbacv1.ClusterRoleBinding:
		default:
			errors = append(errors, prefix+": expected Role, ClusterRole, RoleBinding, or ClusterRoleBinding")
			continue
		}

		// UniversalDeserializer deliberately does not default or convert. Apply
		// the registered upstream defaults before conversion and validation.
		scheme.Default(obj)
		internal, err := scheme.ConvertToVersion(obj, rbacinternal.SchemeGroupVersion)
		if err != nil {
			errors = append(errors, prefix+": "+err.Error())
			continue
		}
		var validationErrors field.ErrorList
		switch typed := internal.(type) {
		case *rbacinternal.Role:
			validationErrors = rbacvalidation.ValidateRole(typed)
		case *rbacinternal.ClusterRole:
			validationErrors = rbacvalidation.ValidateClusterRole(typed, rbacvalidation.ClusterRoleValidationOptions{})
		case *rbacinternal.RoleBinding:
			validationErrors = rbacvalidation.ValidateRoleBinding(typed)
		case *rbacinternal.ClusterRoleBinding:
			validationErrors = rbacvalidation.ValidateClusterRoleBinding(typed)
		default:
			errors = append(errors, prefix+": unexpected internal RBAC type")
			continue
		}
		for _, validationError := range validationErrors {
			errors = append(errors, prefix+": "+validationError.Error())
		}
		metadata, err := apimeta.Accessor(obj)
		if err != nil {
			errors = append(errors, prefix+": "+err.Error())
			continue
		}
		// A List is a materialized store snapshot, not a sequence of creates.
		// Generated names and duplicate identities cannot define such a store.
		if metadata.GetName() == "" {
			errors = append(errors, prefix+".metadata.name: an explicit name is required for a snapshot")
		}
		key := gvk.Kind + "\x00" + metadata.GetNamespace() + "\x00" + metadata.GetName()
		if first, exists := seen[key]; exists {
			errors = append(errors, fmt.Sprintf("%s: duplicate object identity also present at manifest.items[%d]", prefix, first))
		}
		seen[key] = index
		switch typed := obj.(type) {
		case *rbacv1.Role:
			objects.roles = append(objects.roles, typed)
		case *rbacv1.ClusterRole:
			objects.clusterRoles = append(objects.clusterRoles, typed)
		case *rbacv1.RoleBinding:
			objects.roleBindings = append(objects.roleBindings, typed)
		case *rbacv1.ClusterRoleBinding:
			objects.clusterRoleBindings = append(objects.clusterRoleBindings, typed)
		}
	}
	return objects, errors
}

func decodeRequests(data []byte) ([]request, []string) {
	var rawRequests []json.RawMessage
	if err := json.Unmarshal(data, &rawRequests); err != nil || rawRequests == nil {
		return nil, []string{"requests: expected one JSON array"}
	}
	requests := make([]request, 0, len(rawRequests))
	errors := []string{}
	required := []string{"id", "username", "groups", "verb", "apiGroup", "resource", "namespace", "name"}
	for index, raw := range rawRequests {
		prefix := fmt.Sprintf("requests[%d]", index)
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
			errors = append(errors, prefix+": expected an object")
			continue
		}
		var req request
		strictErrors, err := strictjson.UnmarshalStrict(raw, &req)
		if err != nil {
			errors = append(errors, prefix+": "+err.Error())
			continue
		}
		for _, strictError := range strictErrors {
			errors = append(errors, prefix+": "+strictError.Error())
		}
		for _, name := range required {
			if _, exists := fields[name]; !exists {
				errors = append(errors, prefix+"."+name+": required field")
			}
		}
		// The JSON decoder accepts null for several Go value types. The request
		// adapter contract requires actual strings, booleans, and string arrays.
		for _, name := range append(required, "subresource", "resourceRequest", "path") {
			if value, exists := fields[name]; exists && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				errors = append(errors, prefix+"."+name+": null is not permitted")
			}
		}
		if groups, exists := fields["groups"]; exists {
			var entries []json.RawMessage
			if json.Unmarshal(groups, &entries) == nil {
				for groupIndex, entry := range entries {
					if bytes.Equal(bytes.TrimSpace(entry), []byte("null")) {
						errors = append(errors, fmt.Sprintf("%s.groups[%d]: expected a string", prefix, groupIndex))
					}
				}
			}
		}
		requests = append(requests, req)
	}
	return requests, errors
}
