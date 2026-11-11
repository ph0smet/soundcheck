package main

// This adapter executes the pinned production controller. It does not resolve
// selector graphs or derive expected grants. The expected permission state is a
// separate, frozen test input. Only a reference-only copy receives sentinel
// aggregate rules, forcing a native controller update even for empty results.
import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	rbacinformers "k8s.io/client-go/informers/rbac/v1"
	"k8s.io/client-go/kubernetes/fake"
	rbaclisters "k8s.io/client-go/listers/rbac/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/controller/clusterroleaggregation"
	strictjson "sigs.k8s.io/json"
)

type aggregationUpdate struct {
	Name            string              `json:"name"`
	ResourceVersion string              `json:"resource_version"`
	Rules           []rbacv1.PolicyRule `json:"rules"`
}

type aggregationReference struct {
	SchemaVersion      int                 `json:"schema_version"`
	Kind               string              `json:"kind"`
	SourceSHA256       string              `json:"source_sha256"`
	ExpectedSHA256     string              `json:"expected_sha256"`
	Valid              bool                `json:"valid"`
	ValidationErrors   []string            `json:"validation_errors"`
	ControllerExecuted bool                `json:"controller_executed"`
	ExpectedReached    bool                `json:"expected_reached"`
	AggregateRoles     []string            `json:"aggregate_roles"`
	Reconciliations    []string            `json:"reconciliations"`
	Updates            []aggregationUpdate `json:"updates"`
	SeededSnapshot     json.RawMessage     `json:"seeded_snapshot"`
	Snapshot           json.RawMessage     `json:"snapshot"`
}

type aggregationInformer struct {
	informer cache.SharedIndexInformer
	observe  func(string)
}

type orderedAggregationLister struct {
	rbaclisters.ClusterRoleLister
	observe func(string)
}

func (l orderedAggregationLister) List(selector labels.Selector) ([]*rbacv1.ClusterRole, error) {
	roles, err := l.ClusterRoleLister.List(selector)
	// Ordering the in-memory store's enumeration makes the queue deterministic.
	// Selector matching remains the production lister's implementation.
	sort.Slice(roles, func(i, j int) bool { return roles[i].Name < roles[j].Name })
	return roles, err
}

func (l orderedAggregationLister) Get(name string) (*rbacv1.ClusterRole, error) {
	l.observe(name)
	return l.ClusterRoleLister.Get(name)
}

func (i aggregationInformer) Informer() cache.SharedIndexInformer { return i.informer }
func (i aggregationInformer) Lister() rbaclisters.ClusterRoleLister {
	return orderedAggregationLister{rbaclisters.NewClusterRoleLister(i.informer.GetIndexer()), i.observe}
}

func normalizedAggregationRules(rules []rbacv1.PolicyRule) []string {
	unique := map[string]bool{}
	strings := func(values []string) []string {
		set := map[string]bool{}
		for _, value := range values {
			set[value] = true
		}
		out := []string{}
		for value := range set {
			out = append(out, value)
		}
		sort.Strings(out)
		return out
	}
	for _, rule := range rules {
		// Equality of full typed rule sets is only a stop condition against
		// independently supplied expected rules, not an aggregation algorithm.
		value := []interface{}{strings(rule.Verbs), strings(rule.APIGroups),
			strings(rule.Resources), strings(rule.ResourceNames), strings(rule.NonResourceURLs)}
		encoded, _ := json.Marshal(value)
		unique[string(encoded)] = true
	}
	out := []string{}
	for key := range unique {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func aggregationSnapshot(objects inventory, roles map[string]*rbacv1.ClusterRole) (json.RawMessage, error) {
	items := []runtime.Object{}
	for _, role := range objects.roles {
		items = append(items, role)
	}
	for _, role := range objects.clusterRoles {
		if replacement, ok := roles[role.Name]; ok {
			items = append(items, replacement.DeepCopy())
		} else {
			items = append(items, role)
		}
	}
	for _, binding := range objects.roleBindings {
		items = append(items, binding)
	}
	for _, binding := range objects.clusterRoleBindings {
		items = append(items, binding)
	}
	return json.Marshal(map[string]interface{}{"apiVersion": "v1", "kind": "List", "items": items})
}

func runAggregationReference(source, expectedBytes []byte) aggregationReference {
	out := aggregationReference{SchemaVersion: 1, Kind: "upstream_aggregation_controller_reference",
		SourceSHA256: sha256Text(source), ExpectedSHA256: sha256Text(expectedBytes),
		ValidationErrors: []string{}, AggregateRoles: []string{}, Reconciliations: []string{}, Updates: []aggregationUpdate{}}
	objects, failures := decodeManifest(source)
	out.ValidationErrors = append(out.ValidationErrors, failures...)
	if len(failures) != 0 {
		return out
	}
	expected := map[string][]rbacv1.PolicyRule{}
	strictErrors, err := strictjson.UnmarshalStrict(expectedBytes, &expected)
	if err != nil || len(strictErrors) != 0 || expected == nil {
		out.ValidationErrors = append(out.ValidationErrors, fmt.Sprintf("expected rules: %v %v", err, strictErrors))
		return out
	}
	seeded := map[string]*rbacv1.ClusterRole{}
	inputs := []runtime.Object{}
	for _, role := range objects.clusterRoles {
		copy := role.DeepCopy()
		copy.ResourceVersion = "0" // Reference-only storage bookkeeping.
		if role.AggregationRule != nil {
			out.AggregateRoles = append(out.AggregateRoles, role.Name)
			if _, ok := expected[role.Name]; !ok {
				out.ValidationErrors = append(out.ValidationErrors, "missing expected aggregate: "+role.Name)
			}
			copy.Rules = []rbacv1.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{"soundcheck-reference.invalid"}, Resources: []string{"sentinel"}}}
		}
		seeded[role.Name] = copy
		inputs = append(inputs, copy)
	}
	sort.Strings(out.AggregateRoles)
	if len(out.AggregateRoles) == 0 || len(out.AggregateRoles) > 512 || len(expected) != len(out.AggregateRoles) {
		out.ValidationErrors = append(out.ValidationErrors, "expected rules must cover exactly 1..512 aggregate roles")
	}
	if len(out.ValidationErrors) != 0 {
		return out
	}
	out.SeededSnapshot, err = aggregationSnapshot(objects, seeded)
	if err != nil {
		out.ValidationErrors = append(out.ValidationErrors, err.Error())
		return out
	}
	out.Valid = true
	client := fake.NewSimpleClientset(inputs...)
	resource := schema.GroupVersionResource{Group: rbacv1.GroupName, Version: "v1", Resource: "clusterroles"}
	var mu sync.Mutex
	updated := map[string]bool{}
	resourceVersion := 0
	reached := make(chan json.RawMessage, 1)
	// Fake storage supplies only apply transport. The real controller constructs
	// every selected/copied rule and sends it through this reactor. Updating the
	// tracker also feeds the real shared informer via its normal watch stream.
	client.PrependReactor("patch", "clusterroles", func(action clienttesting.Action) (bool, runtime.Object, error) {
		patch, ok := action.(clienttesting.PatchAction)
		if !ok || patch.GetPatchType() != types.ApplyPatchType {
			return true, nil, fmt.Errorf("expected controller apply patch")
		}
		var desired rbacv1.ClusterRole
		if err := json.Unmarshal(patch.GetPatch(), &desired); err != nil {
			return true, nil, err
		}
		stored, err := client.Tracker().Get(resource, "", patch.GetName())
		if err != nil {
			return true, nil, err
		}
		role := stored.(*rbacv1.ClusterRole).DeepCopy()
		role.Rules = desired.Rules
		// Shared informers suppress unchanged-resourceVersion update events.
		// Real API storage increments RV; the fake tracker must model that
		// transport behavior or nested propagation can depend on queue order.
		resourceVersion++
		role.ResourceVersion = strconv.Itoa(resourceVersion)
		if err := client.Tracker().Update(resource, role, ""); err != nil {
			return true, nil, err
		}
		mu.Lock()
		defer mu.Unlock()
		out.Updates = append(out.Updates, aggregationUpdate{Name: role.Name, ResourceVersion: role.ResourceVersion, Rules: role.DeepCopy().Rules})
		updated[role.Name] = true
		current := map[string]*rbacv1.ClusterRole{}
		allReached := true
		for _, name := range out.AggregateRoles {
			value, err := client.Tracker().Get(resource, "", name)
			if err != nil {
				return true, nil, err
			}
			current[name] = value.(*rbacv1.ClusterRole).DeepCopy()
			if !updated[name] || !reflect.DeepEqual(normalizedAggregationRules(current[name].Rules), normalizedAggregationRules(expected[name])) {
				allReached = false
			}
		}
		if allReached {
			snapshot, err := aggregationSnapshot(objects, current)
			if err != nil {
				return true, nil, err
			}
			select {
			case reached <- snapshot:
			default:
			}
		}
		return true, role.DeepCopy(), nil
	})
	informer := rbacinformers.NewClusterRoleInformer(client, 0, cache.Indexers{})
	observe := func(name string) {
		mu.Lock()
		defer mu.Unlock()
		out.Reconciliations = append(out.Reconciliations, name)
	}
	controller := clusterroleaggregation.NewClusterRoleAggregation(aggregationInformer{informer, observe}, client.RbacV1())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	informerDone, controllerDone := make(chan struct{}), make(chan struct{})
	out.ControllerExecuted = true
	go func() { defer close(informerDone); informer.Run(ctx.Done()) }()
	go func() { defer close(controllerDone); controller.Run(ctx, 1) }()
	select {
	case snapshot := <-reached:
		out.Snapshot = snapshot
		out.ExpectedReached = true
	case <-ctx.Done():
		out.ValidationErrors = append(out.ValidationErrors, "production controller did not reach the frozen expected rules within 10 seconds")
	}
	cancel()
	<-controllerDone
	<-informerDone
	// Run exits after queue shutdown; a reactor already in flight can finish.
	// Taking the lock ensures the copied update log is not concurrently read.
	mu.Lock()
	result := out
	result.Updates = append([]aggregationUpdate{}, out.Updates...)
	result.Reconciliations = append([]string{}, out.Reconciliations...)
	mu.Unlock()
	return result
}

func aggregationReferenceFiles(args []string) {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: rbac-oracle --aggregate-reference MANIFEST.json EXPECTED_AGGREGATE_RULES.json")
		os.Exit(2)
	}
	source, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	expected, err := os.ReadFile(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	out := runAggregationReference(source, expected)
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if !out.Valid || !out.ExpectedReached {
		os.Exit(1)
	}
}
