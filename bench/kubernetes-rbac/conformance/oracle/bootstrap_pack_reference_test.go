package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac/bootstrappolicy"
)

func TestBootstrapPackReference(t *testing.T) {
	data, err := bootstrapPackReference()
	if err != nil {
		t.Fatal(err)
	}
	again, err := bootstrapPackReference()
	if err != nil || !bytes.Equal(data, again) {
		t.Fatalf("pack generation is not deterministic: %v", err)
	}
	if !bytes.HasSuffix(data, []byte("\n")) || bytes.HasSuffix(data, []byte("\n\n")) {
		t.Fatal("pack must have one final newline")
	}
	var artifact struct {
		Version string          `json:"kubernetes_version"`
		Packs   []bootstrapPack `json:"packs"`
	}
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.Version != "1.34.0" || len(artifact.Packs) != 4 {
		t.Fatalf("wrong pack shape: %+v", artifact)
	}
	counts := map[string]int{"auth-delegator": 1, "cluster-admin": 1, "extension-apiserver-authentication-reader": 1, "view": 2}
	source, err := selectBootstrapPackSources(bootstrappolicy.NamespaceRoles(),
		append(bootstrappolicy.ClusterRoles(), bootstrappolicy.ControllerRoles()...))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, pack := range artifact.Packs {
		if seen[pack.Name] || len(pack.Objects) != counts[pack.Name] {
			t.Fatalf("wrong or duplicate pack: %s", pack.Name)
		}
		seen[pack.Name] = true
		encoded, _ := json.Marshal(map[string]interface{}{"apiVersion": "v1", "kind": "List", "items": pack.Objects})
		objects, failures := decodeManifest(encoded)
		if len(failures) != 0 || len(objects.roleBindings) != 0 || len(objects.clusterRoleBindings) != 0 {
			t.Fatalf("invalid pack or generated binding %s: %v", pack.Name, failures)
		}
		for _, role := range objects.roles {
			role.TypeMeta = metav1.TypeMeta{}
			if !reflect.DeepEqual(role, source.Reader) {
				t.Fatal("reader policy or metadata differs from native source")
			}
		}
		for _, role := range objects.clusterRoles {
			role.TypeMeta = metav1.TypeMeta{}
			var original *rbacv1.ClusterRole
			switch role.Name {
			case "cluster-admin":
				original = source.Admin
			case "system:auth-delegator":
				original = source.Delegate
			case "system:aggregate-to-view":
				original = source.Contributor
			case "view":
				original = source.View.DeepCopy()
				original.Rules = source.Contributor.DeepCopy().Rules
			default:
				t.Fatalf("unexpected emitted object %s", role.Name)
			}
			if !reflect.DeepEqual(role, original) {
				t.Fatalf("pack changed native policy, labels or selector: %s", role.Name)
			}
		}
		if pack.Name == "view" {
			if !reflect.DeepEqual(pack.Dependencies, []string{"ClusterRole/system:aggregate-to-view"}) ||
				!reflect.DeepEqual(pack.Requested, []string{"ClusterRole/view"}) {
				t.Fatal("view contribution is not explicitly recorded")
			}
		} else if len(pack.Dependencies) != 0 {
			t.Fatal("unexpected dependency")
		}
	}
	// Independent coarse expectations guard against selecting a same-name but
	// unrelated role. Complete typed equality above retains every source rule.
	if len(source.Admin.Rules) != 2 || !reflect.DeepEqual(source.Admin.Rules[0].Verbs, []string{"*"}) ||
		!reflect.DeepEqual(source.Admin.Rules[1].NonResourceURLs, []string{"*"}) ||
		len(source.Delegate.Rules) != 2 || len(source.Contributor.Rules) != 11 {
		t.Fatal("pinned literal bootstrap expectations changed")
	}
}

func TestBootstrapPackFeatureGatesFailClosed(t *testing.T) {
	t.Run("selected view rule gate", func(t *testing.T) {
		featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.DynamicResourceAllocation, false)
		if _, err := bootstrapPackReference(); err == nil {
			t.Fatal("non-default selected view rules were labelled as the pinned default pack")
		}
	})
	t.Run("unselected registry gate", func(t *testing.T) {
		featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.ClusterTrustBundle, true)
		if _, err := bootstrapPackReference(); err == nil {
			t.Fatal("changed full bootstrap catalogue was labelled as the pinned default registry")
		}
	})
}

func TestBootstrapPackClosureAndSelectionFailClosed(t *testing.T) {
	namespaces := bootstrappolicy.NamespaceRoles()
	clusters := append(bootstrappolicy.ClusterRoles(), bootstrappolicy.ControllerRoles()...)
	for _, name := range []string{"view", "cluster-admin", "system:auth-delegator", "system:aggregate-to-view"} {
		without := []rbacv1.ClusterRole{}
		for _, role := range clusters {
			if role.Name != name {
				without = append(without, role)
			}
		}
		if _, err := selectBootstrapPackSources(namespaces, without); err == nil {
			t.Fatalf("missing selected role accepted: %s", name)
		}
	}
	if _, err := selectBootstrapPackSources(nil, clusters); err == nil {
		t.Fatal("missing namespaced source accepted")
	}
	duplicate := append(append([]rbacv1.ClusterRole{}, clusters...), clusters[0])
	if _, err := selectBootstrapPackSources(namespaces, duplicate); err == nil {
		t.Fatal("duplicate complete-catalogue identity accepted")
	}
	// This role was not a selected pack object. A selector over only the known
	// contributor would miss it; the full bootstrap catalogue check must fail.
	extra := rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "unexpected-controller-contributor",
		Labels: map[string]string{"rbac.authorization.k8s.io/aggregate-to-view": "true"}}}
	withExtra := append(append([]rbacv1.ClusterRole{}, clusters...), extra)
	if _, err := selectBootstrapPackSources(namespaces, withExtra); err == nil {
		t.Fatal("additional matching contributor outside pack selection ignored")
	}
	source, err := selectBootstrapPackSources(namespaces, clusters)
	if err != nil {
		t.Fatal(err)
	}
	source.View.Labels["test"] = "changed"
	source.Contributor.Rules[0].Verbs[0] = "changed"
	source.Reader.Annotations["test"] = "changed"
	fresh, err := selectBootstrapPackSources(namespaces, clusters)
	if err != nil || fresh.View.Labels["test"] != "" || fresh.Contributor.Rules[0].Verbs[0] == "changed" ||
		fresh.Reader.Annotations["test"] != "" {
		t.Fatal("selection aliased upstream state")
	}
}
