package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac/bootstrappolicy"
)

func TestBootstrapReference(t *testing.T) {
	data, err := bootstrapReference()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(data, []byte("\n")) || bytes.HasSuffix(data, []byte("\n\n")) {
		t.Fatal("expected exactly one final newline")
	}
	again, err := bootstrapReference()
	if err != nil || !bytes.Equal(data, again) {
		t.Fatalf("non-deterministic serialization: %v", err)
	}
	var list struct {
		APIVersion string            `json:"apiVersion"`
		Kind       string            `json:"kind"`
		Items      []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatal(err)
	}
	if list.APIVersion != "v1" || list.Kind != "List" || len(list.Items) != 2 {
		t.Fatalf("unexpected excerpt shape: %+v", list)
	}
	var role rbacv1.Role
	var cluster rbacv1.ClusterRole
	if err := json.Unmarshal(list.Items[0], &role); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(list.Items[1], &cluster); err != nil {
		t.Fatal(err)
	}
	if role.APIVersion != rbacv1.SchemeGroupVersion.String() || role.Kind != "Role" ||
		role.Namespace != "kube-system" || role.Name != "extension-apiserver-authentication-reader" {
		t.Fatalf("unexpected Role: %+v", role)
	}
	if cluster.APIVersion != rbacv1.SchemeGroupVersion.String() || cluster.Kind != "ClusterRole" ||
		cluster.Namespace != "" || cluster.Name != "system:auth-delegator" {
		t.Fatalf("unexpected ClusterRole: %+v", cluster)
	}
	// Literal checks give the selected default policy an independently reviewed
	// expectation; comparison below also requires every upstream field/rule.
	expectedRead := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"},
		ResourceNames: []string{"extension-apiserver-authentication"}, Verbs: []string{"get", "list", "watch"}}}
	expectedDelegate := []rbacv1.PolicyRule{
		{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{"create"}},
		{APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"subjectaccessreviews"}, Verbs: []string{"create"}},
	}
	if !reflect.DeepEqual(role.Rules, expectedRead) || !reflect.DeepEqual(cluster.Rules, expectedDelegate) {
		t.Fatalf("unexpected selected policy: %+v / %+v", role.Rules, cluster.Rules)
	}
	selected, err := selectBootstrapRoles(bootstrappolicy.NamespaceRoles(), bootstrappolicy.ClusterRoles())
	if err != nil {
		t.Fatal(err)
	}
	role.TypeMeta = metav1.TypeMeta{}
	cluster.TypeMeta = metav1.TypeMeta{}
	if !reflect.DeepEqual(&role, selected[0]) || !reflect.DeepEqual(&cluster, selected[1]) {
		t.Fatal("serialized objects lost or changed upstream policy or metadata")
	}
	objects, failures := decodeManifest(data)
	if len(failures) != 0 || len(objects.roles) != 1 || len(objects.clusterRoles) != 1 ||
		len(objects.roleBindings) != 0 || len(objects.clusterRoleBindings) != 0 {
		t.Fatalf("excerpt failed native validation or introduced bindings: %v / %+v", failures, objects)
	}
}

func TestBootstrapReferenceRequiresExactSelection(t *testing.T) {
	roles := bootstrappolicy.NamespaceRoles()
	clusters := bootstrappolicy.ClusterRoles()
	selected, err := selectBootstrapRoles(roles, clusters)
	if err != nil {
		t.Fatal(err)
	}
	role := selected[0].(*rbacv1.Role)
	cluster := selected[1].(*rbacv1.ClusterRole)
	for name, inputs := range map[string]struct {
		roles    map[string][]rbacv1.Role
		clusters []rbacv1.ClusterRole
	}{
		"missing Role":          {nil, clusters},
		"missing ClusterRole":   {roles, nil},
		"duplicate Role":        {map[string][]rbacv1.Role{"kube-system": {*role, *role}}, clusters},
		"duplicate ClusterRole": {roles, []rbacv1.ClusterRole{*cluster, *cluster}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := selectBootstrapRoles(inputs.roles, inputs.clusters); err == nil {
				t.Fatal("ambiguous or incomplete selection accepted")
			}
		})
	}
	// Selection must not mutate the upstream registry via aliased maps/slices.
	role.Labels["test-only"] = "changed"
	role.Rules[0].Verbs[0] = "changed"
	cluster.Annotations["test-only"] = "changed"
	fresh, err := selectBootstrapRoles(roles, clusters)
	if err != nil {
		t.Fatal(err)
	}
	if fresh[0].(*rbacv1.Role).Labels["test-only"] != "" || fresh[0].(*rbacv1.Role).Rules[0].Verbs[0] != "get" ||
		fresh[1].(*rbacv1.ClusterRole).Annotations["test-only"] != "" {
		t.Fatal("selection returned aliased upstream data")
	}
}
