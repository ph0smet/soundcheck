// Policy-change acceptance calls the pinned Kubernetes storage guards. The
// terminal store supplies old objects and native validation without persistence.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"runtime"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	rulevalidation "k8s.io/component-helpers/auth/rbac/validation"
	kapihelper "k8s.io/kubernetes/pkg/apis/core/helper"
	rbacinternal "k8s.io/kubernetes/pkg/apis/rbac"
	rbacinstall "k8s.io/kubernetes/pkg/apis/rbac/install"
	rbacregistry "k8s.io/kubernetes/pkg/registry/rbac"
	clusterrolestrategy "k8s.io/kubernetes/pkg/registry/rbac/clusterrole"
	clusterrolepolicy "k8s.io/kubernetes/pkg/registry/rbac/clusterrole/policybased"
	clusterrolebindingstrategy "k8s.io/kubernetes/pkg/registry/rbac/clusterrolebinding"
	clusterrolebindingpolicy "k8s.io/kubernetes/pkg/registry/rbac/clusterrolebinding/policybased"
	rolestrategy "k8s.io/kubernetes/pkg/registry/rbac/role"
	rolepolicy "k8s.io/kubernetes/pkg/registry/rbac/role/policybased"
	rolebindingstrategy "k8s.io/kubernetes/pkg/registry/rbac/rolebinding"
	rolebindingpolicy "k8s.io/kubernetes/pkg/registry/rbac/rolebinding/policybased"
	rbacresolver "k8s.io/kubernetes/pkg/registry/rbac/validation"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
	strictjson "sigs.k8s.io/json"
)

type policyChangeTarget struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type policyChangeSpec struct {
	SchemaVersion int                `json:"schema_version"`
	Kind          string             `json:"kind"`
	Actor         string             `json:"actor"`
	Operation     string             `json:"operation"`
	Target        policyChangeTarget `json:"target"`
	Requirements  json.RawMessage    `json:"requirements"`
}

type policyChangeAuth struct {
	Attributes          *urlAttributes `json:"attributes"`
	Decision            string         `json:"decision"`
	Reason              string         `json:"reason"`
	Error               string         `json:"error"`
	GrantingRuleIndices []int          `json:"granting_rule_indices"`
}

type policyChangeResolution struct {
	Kind      string              `json:"kind"`
	Namespace string              `json:"namespace"`
	Username  string              `json:"username"`
	Groups    []string            `json:"groups"`
	RoleRef   *rbacv1.RoleRef     `json:"role_ref"`
	Rules     []rbacv1.PolicyRule `json:"rules"`
	Error     string              `json:"error"`
}

type policyChangeCoverage struct {
	OwnerRules    []rbacv1.PolicyRule `json:"owner_rules"`
	RequiredRules []rbacv1.PolicyRule `json:"required_rules"`
	Covered       bool                `json:"covered"`
	MissingRules  []rbacv1.PolicyRule `json:"missing_rules"`
}

type policyChangeResult struct {
	SchemaVersion     int                      `json:"schema_version"`
	Kind              string                   `json:"kind"`
	Valid             bool                     `json:"valid"`
	ValidationErrors  []string                 `json:"validation_errors"`
	Initial           *policyChangeAuth        `json:"initial"`
	Special           []policyChangeAuth       `json:"special"`
	Resolutions       []policyChangeResolution `json:"resolutions"`
	Coverage          []policyChangeCoverage   `json:"coverage"`
	ActorRules        []rbacv1.PolicyRule      `json:"actor_rules"`
	OnlyGCFields      bool                     `json:"only_gc_fields"`
	StorageCalls      int                      `json:"storage_calls"`
	StorageValidation []string                 `json:"storage_validation"`
	GuardAccepted     bool                     `json:"guard_accepted"`
	Accepted          bool                     `json:"accepted"`
	Error             string                   `json:"error"`
	ErrorReason       string                   `json:"error_reason"`
	HTTPStatus        int                      `json:"http_status"`
}

func emptyPolicyChangeResult() policyChangeResult {
	return policyChangeResult{SchemaVersion: 1, Kind: "rbac_policy_change_native", ValidationErrors: []string{},
		Special: []policyChangeAuth{}, Resolutions: []policyChangeResolution{}, Coverage: []policyChangeCoverage{}, ActorRules: []rbacv1.PolicyRule{}, StorageValidation: []string{}}
}

func policyChangeScheme() *kruntime.Scheme {
	scheme := kruntime.NewScheme()
	metav1.AddToGroupVersion(scheme, metav1.SchemeGroupVersion)
	rbacinstall.Install(scheme)
	return scheme
}

func policyChangeRules(rules []rbacv1.PolicyRule) []rbacv1.PolicyRule {
	return append([]rbacv1.PolicyRule{}, rules...)
}

// Delegate every actual lookup to the unchanged native resolver. Capturing its
// operands does not replace ConfirmNoEscalation or the native storage guard.
type policyChangeResolver struct {
	rbacresolver.AuthorizationRuleResolver
	result *policyChangeResult
}

func (r *policyChangeResolver) RulesFor(ctx context.Context, actor user.Info, namespace string) ([]rbacv1.PolicyRule, error) {
	rules, err := r.AuthorizationRuleResolver.RulesFor(ctx, actor, namespace)
	entry := policyChangeResolution{Kind: "owner", Namespace: namespace, Username: actor.GetName(), Groups: append([]string{}, actor.GetGroups()...), Rules: policyChangeRules(rules)}
	if err != nil {
		entry.Error = err.Error()
	}
	r.result.Resolutions = append(r.result.Resolutions, entry)
	return rules, err
}

func (r *policyChangeResolver) GetRoleReferenceRules(ctx context.Context, ref rbacv1.RoleRef, namespace string) ([]rbacv1.PolicyRule, error) {
	rules, err := r.AuthorizationRuleResolver.GetRoleReferenceRules(ctx, ref, namespace)
	entry := policyChangeResolution{Kind: "reference", Namespace: namespace, Groups: []string{}, RoleRef: &ref, Rules: policyChangeRules(rules)}
	if err != nil {
		entry.Error = err.Error()
	}
	r.result.Resolutions = append(r.result.Resolutions, entry)
	return rules, err
}

// Match the StandardStorage contract used by Kubernetes' own policybased tests:
// Update must evaluate the wrapped UpdatedObjectInfo against the old object.
// Real native strategy validation follows the wrapper before accepting a write.
type policyChangeStore struct {
	rest.StandardStorage
	old      kruntime.Object
	strategy rest.RESTCreateUpdateStrategy
	result   *policyChangeResult
}

func (s *policyChangeStore) validate(errors field.ErrorList) error {
	for _, e := range errors {
		s.result.StorageValidation = append(s.result.StorageValidation, e.Error())
	}
	if len(errors) != 0 {
		return apierrors.NewInvalid(rbacinternal.Kind("PolicyChange"), "target", errors)
	}
	return nil
}

func (s *policyChangeStore) Create(ctx context.Context, obj kruntime.Object, validation rest.ValidateObjectFunc, options *metav1.CreateOptions) (kruntime.Object, error) {
	s.result.StorageCalls++
	if err := s.validate(s.strategy.Validate(ctx, obj)); err != nil {
		return nil, err
	}
	if validation != nil {
		if err := validation(ctx, obj); err != nil {
			return nil, err
		}
	}
	return obj, nil
}

func (s *policyChangeStore) Update(ctx context.Context, name string, info rest.UpdatedObjectInfo, createValidation rest.ValidateObjectFunc, updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (kruntime.Object, bool, error) {
	obj, err := info.UpdatedObject(ctx, s.old.DeepCopyObject())
	if err != nil {
		return nil, false, err
	}
	s.result.StorageCalls++
	// Snapshot metadata deliberately omits resourceVersion. Assign equal fixture
	// versions only after the policy wrapper/GC comparison, for native update
	// validation; no optimistic concurrency or storage outcome is simulated.
	old := s.old.DeepCopyObject()
	oldMeta, _ := apimeta.Accessor(old)
	newMeta, _ := apimeta.Accessor(obj)
	oldMeta.SetResourceVersion("fixture")
	newMeta.SetResourceVersion("fixture")
	if err := s.validate(s.strategy.ValidateUpdate(ctx, obj, old)); err != nil {
		return nil, false, err
	}
	if updateValidation != nil {
		if err := updateValidation(ctx, obj, old); err != nil {
			return nil, false, err
		}
	}
	return obj, false, nil
}

func policyChangeInternal(objects inventory, target policyChangeTarget, scheme *kruntime.Scheme) (kruntime.Object, error) {
	var selected kruntime.Object
	switch target.Kind {
	case "Role":
		for _, obj := range objects.roles {
			if obj.Name == target.Name && obj.Namespace == target.Namespace {
				selected = obj
			}
		}
	case "ClusterRole":
		for _, obj := range objects.clusterRoles {
			if obj.Name == target.Name {
				selected = obj
			}
		}
	case "RoleBinding":
		for _, obj := range objects.roleBindings {
			if obj.Name == target.Name && obj.Namespace == target.Namespace {
				selected = obj
			}
		}
	case "ClusterRoleBinding":
		for _, obj := range objects.clusterRoleBindings {
			if obj.Name == target.Name {
				selected = obj
			}
		}
	default:
		return nil, fmt.Errorf("unsupported target kind")
	}
	if selected == nil {
		return nil, nil
	}
	return scheme.ConvertToVersion(selected.DeepCopyObject(), rbacinternal.SchemeGroupVersion)
}

func decodePolicyChangeSpec(data []byte) (policyChangeSpec, *user.DefaultInfo, error) {
	var spec policyChangeSpec
	strictErrors, err := strictjson.UnmarshalStrict(data, &spec)
	if err != nil {
		return spec, nil, err
	}
	if len(strictErrors) != 0 {
		return spec, nil, fmt.Errorf("invalid contract: %v", strictErrors)
	}
	if spec.SchemaVersion != 1 || spec.Kind != "kubernetes-rbac-policy-change" || (spec.Operation != "create" && spec.Operation != "update-existing") {
		return spec, nil, fmt.Errorf("unsupported policy-change contract version/kind/operation")
	}
	var raw struct {
		Target map[string]json.RawMessage `json:"target"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return spec, nil, err
	}
	namespaced := spec.Target.Kind == "Role" || spec.Target.Kind == "RoleBinding"
	if namespaced {
		if spec.Target.Namespace == "" {
			return spec, nil, fmt.Errorf("namespaced target requires namespace")
		}
	} else {
		if spec.Target.Kind != "ClusterRole" && spec.Target.Kind != "ClusterRoleBinding" {
			return spec, nil, fmt.Errorf("unsupported target kind")
		}
		if !bytes.Equal(bytes.TrimSpace(raw.Target["namespace"]), []byte("null")) {
			return spec, nil, fmt.Errorf("cluster target namespace must be null")
		}
	}
	if spec.Target.Name == "" {
		return spec, nil, fmt.Errorf("target name required")
	}
	var requirements struct {
		Context struct {
			Identities []struct {
				Username string   `json:"username"`
				Groups   []string `json:"groups"`
			} `json:"identities"`
		} `json:"context"`
	}
	if err := json.Unmarshal(spec.Requirements, &requirements); err != nil {
		return spec, nil, err
	}
	var actor *user.DefaultInfo
	for _, identity := range requirements.Context.Identities {
		if identity.Username != spec.Actor {
			continue
		}
		if actor != nil {
			return spec, nil, fmt.Errorf("duplicate frozen actor")
		}
		actor = &user.DefaultInfo{Name: identity.Username, Groups: append([]string{}, identity.Groups...)}
	}
	if actor == nil || actor.Name == "" {
		return spec, nil, fmt.Errorf("actor is absent from frozen identities")
	}
	for _, group := range actor.Groups {
		if group == user.SystemPrivilegedGroup {
			return spec, nil, fmt.Errorf("system:masters actor is outside policy-change v1")
		}
	}
	return spec, actor, nil
}

// Preserve every submitted field and array position when checking that only
// the target changes. Map order and the List's object order are irrelevant.
func policyChangeRawObjects(data []byte) (map[string][]byte, error) {
	var list struct {
		Items []map[string]interface{} `json:"items"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	objects := map[string][]byte{}
	for _, obj := range list.Items {
		meta, ok := obj["metadata"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("missing object metadata")
		}
		kind, _ := obj["kind"].(string)
		name, _ := meta["name"].(string)
		namespace, _ := meta["namespace"].(string)
		key := kind + "\x00" + namespace + "\x00" + name
		if _, exists := objects[key]; exists {
			return nil, fmt.Errorf("duplicate object")
		}
		canonical, err := json.Marshal(obj)
		if err != nil {
			return nil, err
		}
		objects[key] = canonical
	}
	return objects, nil
}

func policyChangeSpecFields(obj policyObject) []byte {
	var value interface{}
	if obj.RoleRef == nil {
		value = policyChangeRules(obj.Rules)
	} else {
		value = append([]rbacv1.Subject{}, obj.Subjects...)
	}
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func policyChangeBoundary(beforeJSON, afterJSON []byte, before, after inventory, spec policyChangeSpec) error {
	left, err := policyChangeRawObjects(beforeJSON)
	if err != nil {
		return err
	}
	right, err := policyChangeRawObjects(afterJSON)
	if err != nil {
		return err
	}
	key := spec.Target.Kind + "\x00" + spec.Target.Namespace + "\x00" + spec.Target.Name
	for k, value := range left {
		if k == key {
			continue
		}
		if !bytes.Equal(value, right[k]) {
			return fmt.Errorf("non-target object changed: %q", k)
		}
	}
	for k := range right {
		if k != key {
			if _, exists := left[k]; !exists {
				return fmt.Errorf("non-target object added: %q", k)
			}
		}
	}
	old, oldExists := projectPolicies(before)[key]
	next, nextExists := projectPolicies(after)[key]
	if !nextExists || (spec.Operation == "create" && oldExists) || (spec.Operation == "update-existing" && !oldExists) {
		return fmt.Errorf("operation does not match target existence")
	}
	if old.AggregationRule != nil || next.AggregationRule != nil {
		return fmt.Errorf("aggregate target is outside policy-change v1")
	}
	if spec.Operation == "update-existing" {
		if !reflect.DeepEqual(old.RoleRef, next.RoleRef) {
			return fmt.Errorf("roleRef is immutable")
		}
		if bytes.Equal(policyChangeSpecFields(old), policyChangeSpecFields(next)) {
			return fmt.Errorf("no-op or metadata-only update is outside policy-change v1")
		}
	}
	return nil
}

func evaluatePolicyChange(beforeJSON, afterJSON, contractJSON []byte) policyChangeResult {
	out := emptyPolicyChangeResult()
	before, beforeErrors := decodeManifest(beforeJSON)
	after, afterErrors := decodeManifest(afterJSON)
	out.ValidationErrors = append(out.ValidationErrors, beforeErrors...)
	out.ValidationErrors = append(out.ValidationErrors, afterErrors...)
	spec, actor, err := decodePolicyChangeSpec(contractJSON)
	if err != nil {
		out.ValidationErrors = append(out.ValidationErrors, err.Error())
	}
	if len(out.ValidationErrors) != 0 {
		return out
	}
	if err := policyChangeBoundary(beforeJSON, afterJSON, before, after, spec); err != nil {
		out.ValidationErrors = append(out.ValidationErrors, err.Error())
		return out
	}
	scheme := policyChangeScheme()
	old, err := policyChangeInternal(before, spec.Target, scheme)
	if err != nil {
		out.ValidationErrors = append(out.ValidationErrors, err.Error())
		return out
	}
	obj, err := policyChangeInternal(after, spec.Target, scheme)
	if err != nil {
		out.ValidationErrors = append(out.ValidationErrors, err.Error())
		return out
	}
	if obj == nil || (spec.Operation == "create" && old != nil) || (spec.Operation == "update-existing" && old == nil) {
		out.ValidationErrors = append(out.ValidationErrors, "operation does not match before/after target existence")
		return out
	}
	// The corpus independently fixes the single-object boundary. Target checks
	// here also reject known native exceptions excluded from this version.
	for _, target := range []kruntime.Object{old, obj} {
		if cr, ok := target.(*rbacinternal.ClusterRole); ok && cr.AggregationRule != nil {
			out.ValidationErrors = append(out.ValidationErrors, "aggregate target is outside policy-change v1")
			return out
		}
	}
	if old != nil {
		out.OnlyGCFields = rbacregistry.IsOnlyMutatingGCFields(obj, old, kapihelper.Semantic)
	}
	resolver, static := rbacresolver.NewTestRuleResolver(before.roles, before.roleBindings, before.clusterRoles, before.clusterRoleBindings)
	actorRules, resolutionError := resolver.RulesFor(context.Background(), actor, spec.Target.Namespace)
	if resolutionError != nil {
		out.ValidationErrors = append(out.ValidationErrors, "incomplete actor rule resolution: "+resolutionError.Error())
		return out
	}
	out.ActorRules = policyChangeRules(actorRules)
	nativeAuth := rbacauthorizer.New(static, static, static, static)
	tracedResolver := &policyChangeResolver{AuthorizationRuleResolver: resolver, result: &out}
	capture := func(attrs authorizer.Attributes) policyChangeAuth {
		d, reason, err := nativeAuth.Authorize(context.Background(), attrs)
		entry := policyChangeAuth{Attributes: controllerAttributes(attrs), Decision: decisionName(d), Reason: reason, GrantingRuleIndices: []int{}}
		for index, rule := range actorRules {
			if rbacauthorizer.RuleAllows(attrs, &rule) {
				entry.GrantingRuleIndices = append(entry.GrantingRuleIndices, index)
			}
		}
		if err != nil {
			entry.Error = err.Error()
		}
		return entry
	}
	initialAuth := authorizer.AuthorizerFunc(func(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
		entry := capture(attrs)
		out.Initial = &entry
		if entry.Decision == "Allow" {
			return authorizer.DecisionAllow, entry.Reason, nil
		}
		return authorizer.DecisionNoOpinion, entry.Reason, nil
	})
	specialAuth := authorizer.AuthorizerFunc(func(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
		entry := capture(attrs)
		out.Special = append(out.Special, entry)
		if entry.Decision == "Allow" {
			return authorizer.DecisionAllow, entry.Reason, nil
		}
		return authorizer.DecisionNoOpinion, entry.Reason, nil
	})
	store := &policyChangeStore{old: old, result: &out}
	var storage rest.StandardStorage
	resource := ""
	switch spec.Target.Kind {
	case "Role":
		resource = "roles"
		store.strategy = rolestrategy.Strategy
		storage = rolepolicy.NewStorage(store, specialAuth, tracedResolver)
	case "ClusterRole":
		resource = "clusterroles"
		store.strategy = clusterrolestrategy.Strategy
		storage = clusterrolepolicy.NewStorage(store, specialAuth, tracedResolver)
	case "RoleBinding":
		resource = "rolebindings"
		store.strategy = rolebindingstrategy.Strategy
		storage = rolebindingpolicy.NewStorage(store, specialAuth, tracedResolver)
	case "ClusterRoleBinding":
		resource = "clusterrolebindings"
		store.strategy = clusterrolebindingstrategy.Strategy
		storage = clusterrolebindingpolicy.NewStorage(store, specialAuth, tracedResolver)
	}
	path := "/apis/rbac.authorization.k8s.io/v1"
	if spec.Target.Namespace != "" {
		path += "/namespaces/" + url.PathEscape(spec.Target.Namespace)
	}
	path += "/" + resource
	method := "POST"
	if spec.Operation == "update-existing" {
		method = "PUT"
		path += "/" + url.PathEscape(spec.Target.Name)
	}
	entry := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		info, _ := apirequest.RequestInfoFrom(req.Context())
		ctx := apirequest.WithNamespace(req.Context(), info.Namespace)
		var storageError error
		if spec.Operation == "create" {
			_, storageError = storage.Create(ctx, obj, nil, &metav1.CreateOptions{})
		} else {
			_, _, storageError = storage.Update(ctx, spec.Target.Name, rest.DefaultUpdatedObjectInfo(obj), nil, nil, false, &metav1.UpdateOptions{})
		}
		out.GuardAccepted = out.StorageCalls == 1
		if storageError != nil {
			out.Error = storageError.Error()
			out.ErrorReason = string(apierrors.ReasonForError(storageError))
			if status, ok := storageError.(apierrors.APIStatus); ok {
				w.WriteHeader(int(status.Status().Code))
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}
		out.Accepted = true
		if spec.Operation == "create" {
			w.WriteHeader(http.StatusCreated)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	})
	factory := &apirequest.RequestInfoFactory{APIPrefixes: sets.NewString("api", "apis"), GrouplessAPIPrefixes: sets.NewString("api")}
	handler := filters.WithRequestInfo(filters.WithAuthorization(entry, initialAuth, serializer.NewCodecFactory(scheme)), factory)
	req := httptest.NewRequest(method, path, nil)
	req = req.WithContext(apirequest.WithUser(req.Context(), actor))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	out.HTTPStatus = response.Code
	// Report native Covers over exactly the operands observed at the actual
	// wrapper's RulesFor call. This supplements, rather than predicts, its result.
	var required []rbacv1.PolicyRule
	projected := projectPolicies(after)[spec.Target.Kind+"\x00"+spec.Target.Namespace+"\x00"+spec.Target.Name]
	if projected.RoleRef == nil {
		required = projected.Rules
	}
	for _, resolution := range out.Resolutions {
		if resolution.Kind == "reference" {
			required = resolution.Rules
		}
		if resolution.Kind == "owner" {
			covered, missing := rulevalidation.Covers(resolution.Rules, required)
			out.Coverage = append(out.Coverage, policyChangeCoverage{OwnerRules: policyChangeRules(resolution.Rules), RequiredRules: policyChangeRules(required), Covered: covered, MissingRules: policyChangeRules(missing)})
		}
	}
	out.Valid = true
	return out
}

func policyChangeReferenceFiles(paths []string) {
	out := emptyPolicyChangeResult()
	code := 2
	if len(paths) != 3 {
		out.ValidationErrors = append(out.ValidationErrors, "usage: --policy-change-reference BEFORE.json AFTER.json CONTRACT.json")
	} else {
		data := make([][]byte, 3)
		for i, path := range paths {
			var err error
			data[i], err = os.ReadFile(path)
			if err != nil {
				out.ValidationErrors = append(out.ValidationErrors, err.Error())
			}
		}
		if len(out.ValidationErrors) == 0 {
			out = evaluatePolicyChange(data[0], data[1], data[2])
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

func policyChangeRuntimeInfo() map[string]interface{} {
	functions := map[string]interface{}{}
	for label, function := range map[string]interface{}{
		"request-info": filters.WithRequestInfo, "request-classifier": (*apirequest.RequestInfoFactory).NewRequestInfo,
		"authorization-filter": filters.WithAuthorization, "authorizer-attributes": filters.GetAuthorizerAttributes,
		"rbac-authorizer": (*rbacauthorizer.RBACAuthorizer).Authorize, "role-escalation": rbacregistry.RoleEscalationAuthorized,
		"binding-authorization": rbacregistry.BindingAuthorized, "superuser": rbacregistry.EscalationAllowed,
		"gc-fields": rbacregistry.IsOnlyMutatingGCFields, "rules-for": (*rbacresolver.DefaultRuleResolver).RulesFor,
		"role-reference": (*rbacresolver.DefaultRuleResolver).GetRoleReferenceRules, "confirm-no-escalation": rbacresolver.ConfirmNoEscalation,
		"covers": rulevalidation.Covers, "role-create": (*rolepolicy.Storage).Create, "role-update": (*rolepolicy.Storage).Update,
		"clusterrole-create": (*clusterrolepolicy.Storage).Create, "clusterrole-update": (*clusterrolepolicy.Storage).Update,
		"rolebinding-create": (*rolebindingpolicy.Storage).Create, "rolebinding-update": (*rolebindingpolicy.Storage).Update,
		"clusterrolebinding-create": (*clusterrolebindingpolicy.Storage).Create, "clusterrolebinding-update": (*clusterrolebindingpolicy.Storage).Update,
	} {
		f := runtime.FuncForPC(reflect.ValueOf(function).Pointer())
		file, line := f.FileLine(f.Entry())
		functions[label] = map[string]interface{}{"function": f.Name(), "file": file, "line": line}
	}
	return map[string]interface{}{"schema_version": 1, "kind": "rbac_policy_change_native_linkage", "go_version": runtime.Version(), "modules": applyRuntimeInfo()["modules"], "functions": functions}
}
