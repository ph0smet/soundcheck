package main

// Bootstrap packs are explicit upstream-policy assumptions, not observed cluster
// state. Native selectors inspect the entire upstream bootstrap ClusterRole
// catalogue before the small view closure is materialized by the production
// aggregation controller. No RoleBinding or ClusterRoleBinding is generated.
import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac/bootstrappolicy"
)

type bootstrapPack struct {
	Name         string            `json:"name"`
	Requested    []string          `json:"requested_objects"`
	Dependencies []string          `json:"dependency_objects"`
	Objects      []json.RawMessage `json:"objects"`
}

type bootstrapPackSource struct {
	Reader      *rbacv1.Role
	Admin       *rbacv1.ClusterRole
	Delegate    *rbacv1.ClusterRole
	View        *rbacv1.ClusterRole
	Contributor *rbacv1.ClusterRole
}

func selectBootstrapPackSources(namespaces map[string][]rbacv1.Role, clusters []rbacv1.ClusterRole) (bootstrapPackSource, error) {
	result := bootstrapPackSource{}
	byName := map[string]*rbacv1.ClusterRole{}
	for i := range clusters {
		role := clusters[i].DeepCopy()
		if role.Namespace != "" || byName[role.Name] != nil {
			return result, fmt.Errorf("bootstrap catalogue has a namespaced or duplicate ClusterRole %q", role.Name)
		}
		byName[role.Name] = role
	}
	for _, roles := range namespaces {
		for i := range roles {
			role := roles[i]
			if role.Name == "extension-apiserver-authentication-reader" {
				if role.Namespace != "kube-system" || result.Reader != nil {
					return result, fmt.Errorf("bootstrap reader Role has an ambiguous identity")
				}
				result.Reader = role.DeepCopy()
			}
		}
	}
	result.Admin = byName["cluster-admin"]
	result.Delegate = byName["system:auth-delegator"]
	result.View = byName["view"]
	result.Contributor = byName["system:aggregate-to-view"]
	if result.Reader == nil || result.Admin == nil || result.Delegate == nil || result.View == nil || result.Contributor == nil {
		return result, fmt.Errorf("pinned bootstrap pack source is missing a selected role")
	}
	if result.View.AggregationRule == nil || len(result.View.AggregationRule.ClusterRoleSelectors) != 1 ||
		result.Contributor.AggregationRule != nil {
		return result, fmt.Errorf("pinned view aggregation shape changed")
	}
	selected := map[string]bool{}
	for _, selector := range result.View.AggregationRule.ClusterRoleSelectors {
		parsed, err := metav1.LabelSelectorAsSelector(&selector)
		if err != nil {
			return result, err
		}
		// Match against ALL upstream ClusterRoles and ControllerRoles, not just
		// the contributor that this particular pinned version is expected to use.
		for _, role := range clusters {
			if role.Name != result.View.Name && parsed.Matches(labels.Set(role.Labels)) {
				selected[role.Name] = true
			}
		}
	}
	if len(selected) != 1 || !selected["system:aggregate-to-view"] {
		return result, fmt.Errorf("view closure differs from the pinned single-contributor pack: %v", selected)
	}
	return result, nil
}

func bootstrapPackReference() ([]byte, error) {
	namespaces := bootstrappolicy.NamespaceRoles()
	// This is the same union used by pkg/registry/rbac/rest/storage_rbac.go.
	clusters := append(bootstrappolicy.ClusterRoles(), bootstrappolicy.ControllerRoles()...)
	sort.Slice(clusters, func(i, j int) bool { return clusters[i].Name < clusters[j].Name })
	source, err := selectBootstrapPackSources(namespaces, clusters)
	if err != nil {
		return nil, err
	}
	// The selected policy is pinned to the upstream v1.34.0 default gates. DRA
	// is the sole feature branch in viewRules; never silently emit another pack.
	if !utilfeature.DefaultFeatureGate.Enabled(features.DynamicResourceAllocation) {
		return nil, fmt.Errorf("bootstrap packs require upstream v1.34.0 default DynamicResourceAllocation=true")
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, rbacv1.AddToScheme} {
		if err := add(scheme); err != nil {
			return nil, err
		}
	}
	codec := serializer.NewCodecFactory(scheme).LegacyCodec(rbacv1.SchemeGroupVersion)
	encode := func(object runtime.Object) (json.RawMessage, error) {
		return runtime.Encode(codec, object)
	}
	view, err := encode(source.View)
	if err != nil {
		return nil, err
	}
	contributor, err := encode(source.Contributor)
	if err != nil {
		return nil, err
	}
	seed, err := json.Marshal(map[string]interface{}{"apiVersion": "v1", "kind": "List", "items": []json.RawMessage{view, contributor}})
	if err != nil {
		return nil, err
	}
	expected, err := json.Marshal(map[string][]rbacv1.PolicyRule{"view": source.Contributor.Rules})
	if err != nil {
		return nil, err
	}
	reference := runAggregationReference(seed, expected)
	if !reference.Valid || !reference.ControllerExecuted || !reference.ExpectedReached || len(reference.ValidationErrors) != 0 {
		return nil, fmt.Errorf("native bootstrap aggregation failed: %v", reference.ValidationErrors)
	}
	resolved, failures := decodeManifest(reference.Snapshot)
	if len(failures) != 0 {
		return nil, fmt.Errorf("native resolved bootstrap snapshot invalid: %v", failures)
	}
	var actualView *rbacv1.ClusterRole
	for _, role := range resolved.clusterRoles {
		if role.Name == "view" {
			actualView = role
		}
	}
	if actualView == nil || !reflect.DeepEqual(normalizedAggregationRules(actualView.Rules), normalizedAggregationRules(source.Contributor.Rules)) {
		return nil, fmt.Errorf("native controller did not produce the complete pinned view rule set")
	}
	// Copy only the production controller's materialized rules. Reference-only
	// fake storage resourceVersions and sentinel seeds are not bootstrap policy.
	source.View.Rules = actualView.DeepCopy().Rules
	pack := func(name, requested string, dependencies []string, objects ...runtime.Object) (bootstrapPack, error) {
		result := bootstrapPack{Name: name, Requested: []string{requested}, Dependencies: dependencies, Objects: []json.RawMessage{}}
		for _, object := range objects {
			data, err := encode(object)
			if err != nil {
				return result, err
			}
			result.Objects = append(result.Objects, data)
		}
		return result, nil
	}
	packs := []bootstrapPack{}
	for _, row := range []struct {
		name, requested string
		dependencies    []string
		objects         []runtime.Object
	}{
		{"auth-delegator", "ClusterRole/system:auth-delegator", []string{}, []runtime.Object{source.Delegate}},
		{"cluster-admin", "ClusterRole/cluster-admin", []string{}, []runtime.Object{source.Admin}},
		{"extension-apiserver-authentication-reader", "Role/kube-system/extension-apiserver-authentication-reader", []string{}, []runtime.Object{source.Reader}},
		{"view", "ClusterRole/view", []string{"ClusterRole/system:aggregate-to-view"}, []runtime.Object{source.View, source.Contributor}},
	} {
		value, err := pack(row.name, row.requested, row.dependencies, row.objects...)
		if err != nil {
			return nil, err
		}
		packs = append(packs, value)
	}
	clusterBytes, err := json.Marshal(clusters)
	if err != nil {
		return nil, err
	}
	namespaceBytes, err := json.Marshal(namespaces)
	if err != nil {
		return nil, err
	}
	// These full typed-catalogue pins were captured from the reviewed upstream
	// default feature gates. They also catch feature branches outside the small
	// selected packs, rather than labelling a modified registry as defaults.
	if len(clusters) != 68 || sha256Text(clusterBytes) != "218810b8f27f17916184212b5ab9b01dccc72db825afd6f74ffab4f962d51ece" ||
		sha256Text(namespaceBytes) != "08162921ad6294154629ab37160a9b3024ea8a30fa6ac453c55b3fc78566cf7a" {
		return nil, fmt.Errorf("bootstrap catalogue differs from pinned v1.34.0 upstream defaults")
	}
	result := map[string]interface{}{
		"schema_version": 1, "kind": "kubernetes-bootstrap-reference-packs", "kubernetes_version": "1.34.0",
		"upstream": map[string]interface{}{
			"module": "k8s.io/kubernetes@v1.34.0", "commit": "f28b4c9efbca5c5c0af716d9f2d5702667ee8a45",
			"module_sum": "h1:NvUrwPAVB4W3mSOpJ/RtNGHWWYyUP/xPaX5rUSpzA0w=", "license": "Apache-2.0",
		},
		"configuration": map[string]interface{}{"feature_gates": "upstream-defaults", "DynamicResourceAllocation": true},
		"source_catalogue": map[string]interface{}{
			"cluster_role_count": len(clusters), "cluster_roles_sha256": sha256Text(clusterBytes),
			"namespace_roles_sha256": sha256Text(namespaceBytes),
		},
		"aggregation": map[string]interface{}{
			"role": "view", "contributors": []string{"system:aggregate-to-view"}, "native_controller_executed": true,
			"selection_scope": "all upstream ClusterRoles and ControllerRoles",
		},
		"packs": packs,
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func bootstrapPackReferenceFiles(args []string) {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: rbac-oracle --bootstrap-pack-reference")
		os.Exit(2)
	}
	modules := applyRuntimeInfo()["modules"].(map[string]string)
	for path, version := range map[string]string{
		"k8s.io/kubernetes": "v1.34.0", "k8s.io/api": "v0.34.0",
		"k8s.io/apimachinery": "v0.34.0", "k8s.io/apiserver": "v0.34.0", "k8s.io/client-go": "v0.34.0",
	} {
		if modules[path] != version {
			fmt.Fprintf(os.Stderr, "bootstrap reference requires %s@%s, got %q\n", path, version, modules[path])
			os.Exit(1)
		}
	}
	data, err := bootstrapPackReference()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(data); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
