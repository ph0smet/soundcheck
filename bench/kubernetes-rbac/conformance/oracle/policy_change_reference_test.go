package main

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	kapihelper "k8s.io/kubernetes/pkg/apis/core/helper"
	rbacinternal "k8s.io/kubernetes/pkg/apis/rbac"
	rbacregistry "k8s.io/kubernetes/pkg/registry/rbac"
	clusterrolestrategy "k8s.io/kubernetes/pkg/registry/rbac/clusterrole"
	clusterrolepolicy "k8s.io/kubernetes/pkg/registry/rbac/clusterrole/policybased"
	rolebindingstrategy "k8s.io/kubernetes/pkg/registry/rbac/rolebinding"
	rolebindingpolicy "k8s.io/kubernetes/pkg/registry/rbac/rolebinding/policybased"
	rbacresolver "k8s.io/kubernetes/pkg/registry/rbac/validation"
)

func changeTestBytes(value interface{}) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func changeTestRole(kind, name, namespace string, rules []rbacv1.PolicyRule) map[string]interface{} {
	return map[string]interface{}{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind,
		"metadata": map[string]interface{}{"name": name, "namespace": namespace}, "rules": rules}
}

func changeTestBinding(kind, name, namespace, roleKind, roleName, actor string) map[string]interface{} {
	return map[string]interface{}{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind,
		"metadata": map[string]interface{}{"name": name, "namespace": namespace},
		"roleRef":  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: roleKind, Name: roleName},
		"subjects": []rbacv1.Subject{{APIGroup: "rbac.authorization.k8s.io", Kind: "User", Name: actor}}}
}

func changeTestFixture(kind, operation string, covered, initial, explicit bool) ([]byte, []byte, []byte) {
	ns := ""
	var wireNamespace interface{}
	if kind == "Role" || kind == "RoleBinding" {
		ns = "team-a"
		wireNamespace = ns
	}
	resources := map[string]string{"Role": "roles", "ClusterRole": "clusterroles", "RoleBinding": "rolebindings", "ClusterRoleBinding": "clusterrolebindings"}
	verb := "create"
	if operation == "update-existing" {
		verb = "update"
	}
	rules := []rbacv1.PolicyRule{}
	if initial {
		rules = append(rules, rbacv1.PolicyRule{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{resources[kind]}, Verbs: []string{verb}})
	}
	required := rbacv1.PolicyRule{APIGroups: []string{"future.example.test"}, Resources: []string{"novelresources/arbitrary"}, Verbs: []string{"frobnicate"}, ResourceNames: []string{"a", "b"}}
	if covered {
		rules = append(rules, required)
	}
	if explicit {
		special, resource, name := "escalate", resources[kind], ""
		if operation == "update-existing" {
			name = "target"
		}
		if kind == "RoleBinding" || kind == "ClusterRoleBinding" {
			special, resource, name = "bind", "clusterroles", "referenced"
		}
		rules = append(rules, rbacv1.PolicyRule{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{resource}, Verbs: []string{special}, ResourceNames: []string{name}})
	}
	items := []interface{}{changeTestRole("ClusterRole", "actor-authority", "", rules), changeTestBinding("ClusterRoleBinding", "actor-authority", "", "ClusterRole", "actor-authority", "deployer")}
	var target, old map[string]interface{}
	if kind == "Role" || kind == "ClusterRole" {
		target = changeTestRole(kind, "target", ns, []rbacv1.PolicyRule{required})
		old = changeTestRole(kind, "target", ns, []rbacv1.PolicyRule{})
	} else {
		items = append(items, changeTestRole("ClusterRole", "referenced", "", []rbacv1.PolicyRule{required}))
		target = changeTestBinding(kind, "target", ns, "ClusterRole", "referenced", "recipient")
		old = changeTestBinding(kind, "target", ns, "ClusterRole", "referenced", "old-recipient")
	}
	beforeItems := append([]interface{}{}, items...)
	if operation == "update-existing" {
		beforeItems = append(beforeItems, old)
	}
	before := map[string]interface{}{"apiVersion": "v1", "kind": "List", "items": beforeItems}
	after := map[string]interface{}{"apiVersion": "v1", "kind": "List", "items": append(items, target)}
	spec := map[string]interface{}{"schema_version": 1, "kind": "kubernetes-rbac-policy-change", "actor": "deployer", "operation": operation,
		"target":       map[string]interface{}{"kind": kind, "namespace": wireNamespace, "name": "target"},
		"requirements": map[string]interface{}{"context": map[string]interface{}{"identities": []interface{}{map[string]interface{}{"username": "deployer", "groups": []string{"deployers"}}}}}}
	return changeTestBytes(before), changeTestBytes(after), changeTestBytes(spec)
}

func TestPolicyChangeNativeWrappersAndFullRuleCoverage(t *testing.T) {
	for _, kind := range []string{"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"} {
		for _, operation := range []string{"create", "update-existing"} {
			for _, mode := range []string{"ungranted", "uncovered", "covered", "explicit"} {
				t.Run(kind+"/"+operation+"/"+mode, func(t *testing.T) {
					before, after, spec := changeTestFixture(kind, operation, mode == "covered", mode != "ungranted", mode == "explicit")
					result := evaluatePolicyChange(before, after, spec)
					wanted := mode == "covered" || mode == "explicit"
					if !result.Valid || result.Accepted != wanted || result.GuardAccepted != wanted || result.OnlyGCFields {
						t.Fatalf("unexpected result: %s", changeTestBytes(result))
					}
					if result.Initial == nil || result.Initial.Attributes.APIGroup != "rbac.authorization.k8s.io" {
						t.Fatalf("missing initial attributes: %#v", result.Initial)
					}
					name := ""
					if operation == "update-existing" {
						name = "target"
					}
					if result.Initial.Attributes.Name != name {
						t.Fatalf("body replaced initial name: %#v", result.Initial.Attributes)
					}
					if mode == "ungranted" {
						if len(result.Special) != 0 || len(result.Resolutions) != 0 || result.HTTPStatus != 403 {
							t.Fatal("unguarded storage reached")
						}
						return
					}
					if len(result.Special) != 1 || result.Special[0].Attributes.APIVersion != "*" {
						t.Fatalf("missing special attributes: %#v", result.Special)
					}
					if kind == "RoleBinding" || kind == "ClusterRoleBinding" {
						name = "referenced"
					}
					if result.Special[0].Attributes.Name != name || result.Special[0].Attributes.Namespace != result.Initial.Attributes.Namespace {
						t.Fatalf("wrong special target: %#v", result.Special[0])
					}
					if mode == "explicit" {
						if len(result.Coverage) != 0 || len(result.Resolutions) != 0 {
							t.Fatal("explicit special grant did not bypass coverage")
						}
						return
					}
					if len(result.Coverage) != 1 || result.Coverage[0].Covered != (mode == "covered") {
						t.Fatalf("missing full-policy coverage: %#v", result.Coverage)
					}
					if mode == "uncovered" && len(result.Coverage[0].MissingRules) != 2 {
						t.Fatal("full arbitrary policy obligations were lost")
					}
				})
			}
		}
	}
}

func TestPolicyChangeRejectsFrozenBoundarySubstitutions(t *testing.T) {
	before, after, spec := changeTestFixture("RoleBinding", "update-existing", true, true, false)
	for _, mutation := range []string{"actor", "superuser", "namespace", "roleRef", "metadata-only", "unrelated"} {
		t.Run(mutation, func(t *testing.T) {
			var contract, candidate, baseline map[string]interface{}
			json.Unmarshal(spec, &contract)
			json.Unmarshal(after, &candidate)
			json.Unmarshal(before, &baseline)
			target := candidate["items"].([]interface{})[3].(map[string]interface{})
			switch mutation {
			case "actor":
				contract["actor"] = "recipient"
			case "superuser":
				contract["requirements"].(map[string]interface{})["context"].(map[string]interface{})["identities"].([]interface{})[0].(map[string]interface{})["groups"] = []string{"system:masters"}
			case "namespace":
				contract["target"].(map[string]interface{})["namespace"] = nil
			case "roleRef":
				target["roleRef"].(map[string]interface{})["name"] = "actor-authority"
			case "metadata-only":
				target["subjects"] = baseline["items"].([]interface{})[3].(map[string]interface{})["subjects"]
				target["metadata"].(map[string]interface{})["annotations"] = map[string]string{"note": "edited"}
			case "unrelated":
				candidate["items"].([]interface{})[0].(map[string]interface{})["metadata"].(map[string]interface{})["annotations"] = map[string]string{"note": "edited"}
			}
			result := evaluatePolicyChange(before, changeTestBytes(candidate), changeTestBytes(contract))
			if result.Valid || result.Initial != nil || result.Accepted {
				t.Fatalf("boundary accepted: %s", changeTestBytes(result))
			}
		})
	}
}

func TestPolicyChangeNativeExcludedShortcuts(t *testing.T) {
	role := &rbacinternal.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "target"}, Rules: []rbacinternal.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}}
	for _, field := range []string{"same", "finalizers", "owners", "managed", "annotations", "rules"} {
		next := role.DeepCopy()
		switch field {
		case "finalizers":
			next.Finalizers = []string{"example.test/retain"}
		case "owners":
			next.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "owner", UID: "fixture"}}
		case "managed":
			next.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "fixture"}}
		case "annotations":
			next.Annotations = map[string]string{"changed": "true"}
		case "rules":
			next.Rules = append(next.Rules, next.Rules[0])
		}
		if got := rbacregistry.IsOnlyMutatingGCFields(next, role, kapihelper.Semantic); got != (field != "annotations" && field != "rules") {
			t.Fatalf("wrong native GC behavior for %s: %v", field, got)
		}
	}
	ctx := apirequest.WithUser(context.Background(), &user.DefaultInfo{Name: "administrator", Groups: []string{"system:masters"}})
	if !rbacregistry.EscalationAllowed(ctx) {
		t.Fatal("native privileged bypass changed")
	}
}

func TestPolicyChangeNativeAggregateNeedsResourceAndURLAuthority(t *testing.T) {
	role := &rbacinternal.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "aggregate"}, AggregationRule: &rbacinternal.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{{}}}}
	ctx := apirequest.WithNamespace(apirequest.WithUser(context.Background(), &user.DefaultInfo{Name: "deployer"}), "")
	ctx = apirequest.WithRequestInfo(ctx, &apirequest.RequestInfo{IsResourceRequest: true, APIGroup: "rbac.authorization.k8s.io", Resource: "clusterroles", Verb: "create"})
	for _, includeURLs := range []bool{false, true} {
		rules := []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}
		if includeURLs {
			rules = append(rules, rbacv1.PolicyRule{NonResourceURLs: []string{"*"}, Verbs: []string{"*"}})
		}
		resolver, _ := rbacresolver.NewTestRuleResolver(nil, nil, []*rbacv1.ClusterRole{{ObjectMeta: metav1.ObjectMeta{Name: "authority"}, Rules: rules}}, []*rbacv1.ClusterRoleBinding{{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "authority"}, Subjects: []rbacv1.Subject{{Kind: "User", Name: "deployer"}}}})
		result := emptyPolicyChangeResult()
		terminal := &policyChangeStore{result: &result, strategy: clusterrolestrategy.Strategy}
		noSpecial := authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
			return authorizer.DecisionNoOpinion, "", nil
		})
		storage := clusterrolepolicy.NewStorage(terminal, noSpecial, resolver)
		_, err := storage.Create(ctx, role.DeepCopy(), nil, &metav1.CreateOptions{})
		if (err == nil) != includeURLs {
			t.Fatalf("native aggregate check includeURLs=%v: %v", includeURLs, err)
		}
		result = emptyPolicyChangeResult()
		terminal.result = &result
		terminal.old = role.DeepCopy()
		withoutAggregation := &rbacinternal.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "aggregate"}}
		_, _, err = storage.Update(ctx, "aggregate", rest.DefaultUpdatedObjectInfo(withoutAggregation), nil, nil, false, &metav1.UpdateOptions{})
		if (err == nil) != includeURLs {
			t.Fatalf("removing old native aggregation includeURLs=%v: %v", includeURLs, err)
		}
	}
}

func TestPolicyChangeNativeRoleRefImmutabilitySurvivesBypass(t *testing.T) {
	before, after, _ := changeTestFixture("RoleBinding", "update-existing", false, true, true)
	objects, _ := decodeManifest(before)
	scheme := policyChangeScheme()
	old, _ := policyChangeInternal(objects, policyChangeTarget{Kind: "RoleBinding", Namespace: "team-a", Name: "target"}, scheme)
	updated, _ := decodeManifest(after)
	next, _ := policyChangeInternal(updated, policyChangeTarget{Kind: "RoleBinding", Namespace: "team-a", Name: "target"}, scheme)
	next.(*rbacinternal.RoleBinding).RoleRef.Name = "actor-authority"
	result := emptyPolicyChangeResult()
	store := &policyChangeStore{result: &result, old: old, strategy: nil}
	// The concrete v1 boundary rejects this before authorization; upstream
	// validation independently establishes why no bypass makes it a valid update.
	store.strategy = rolebindingstrategy.Strategy
	resolver, _ := rbacresolver.NewTestRuleResolver(nil, nil, nil, nil)
	bindCalls := 0
	allowBind := authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
		bindCalls++
		return authorizer.DecisionAllow, "fixture explicit bind", nil
	})
	storage := rolebindingpolicy.NewStorage(store, allowBind, resolver)
	ctx := apirequest.WithNamespace(apirequest.WithUser(context.Background(), &user.DefaultInfo{Name: "deployer"}), "team-a")
	_, _, err := storage.Update(ctx, "target", rest.DefaultUpdatedObjectInfo(next), nil, nil, false, &metav1.UpdateOptions{})
	if err == nil || reflect.DeepEqual(next.(*rbacinternal.RoleBinding).RoleRef, old.(*rbacinternal.RoleBinding).RoleRef) {
		t.Fatal("changed roleRef accepted")
	}
	if bindCalls != 1 || result.StorageCalls != 1 || len(result.StorageValidation) == 0 {
		t.Fatal("explicit bind bypass skipped native immutable validation")
	}
}
