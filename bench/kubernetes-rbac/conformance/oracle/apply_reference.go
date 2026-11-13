// The SSA reference runs the pinned authorization filter, PATCH handler, field
// manager, resource strategies and generic store. Only storage state is faked.
// Native DryRunnableStorage drives the real create/update validation branches;
// this adapter never decides which authorization callback should be invoked.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/handlers"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	registry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	_ "k8s.io/kubernetes/pkg/apis/apps/install"
	_ "k8s.io/kubernetes/pkg/apis/core/install"
	_ "k8s.io/kubernetes/pkg/apis/discovery/install"
	deployment "k8s.io/kubernetes/pkg/registry/apps/deployment"
	configmap "k8s.io/kubernetes/pkg/registry/core/configmap"
	endpoint "k8s.io/kubernetes/pkg/registry/core/endpoint"
	node "k8s.io/kubernetes/pkg/registry/core/node"
	pod "k8s.io/kubernetes/pkg/registry/core/pod"
	secret "k8s.io/kubernetes/pkg/registry/core/secret"
	service "k8s.io/kubernetes/pkg/registry/core/service"
	endpointslice "k8s.io/kubernetes/pkg/registry/discovery/endpointslice"
	rbacresolver "k8s.io/kubernetes/pkg/registry/rbac/validation"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
	strictjson "sigs.k8s.io/json"
)

type applyRequest struct {
	ID              string   `json:"id"`
	Username        string   `json:"username"`
	Groups          []string `json:"groups"`
	Operation       string   `json:"operation"`
	APIGroup        string   `json:"apiGroup"`
	Resource        string   `json:"resource"`
	Namespace       string   `json:"namespace"`
	Name            string   `json:"name"`
	Subresource     string   `json:"subresource"`
	ResourceRequest bool     `json:"resourceRequest"`
}

type applyStage struct {
	Attributes urlAttributes `json:"attributes"`
	Decision   string        `json:"decision"`
	Reason     string        `json:"reason"`
	Error      string        `json:"error"`
}

type applyDecision struct {
	decision
	Stages         []applyStage `json:"stages"`
	HTTPStatus     int          `json:"http_status"`
	HandlerEntered bool         `json:"handler_entered"`
	StorageReads   int          `json:"storage_reads"`
}

type applyResult struct {
	SchemaVersion    int             `json:"schema_version"`
	Kind             string          `json:"kind"`
	Valid            bool            `json:"valid"`
	ValidationErrors []string        `json:"validation_errors"`
	Decisions        []applyDecision `json:"decisions"`
}

func emptyApplyResult() applyResult {
	return applyResult{SchemaVersion: 1, Kind: "rbac_apply_authorization", ValidationErrors: []string{}, Decisions: []applyDecision{}}
}

func applyReferenceFiles(args []string) {
	out, code := emptyApplyResult(), 2
	if len(args) != 2 {
		out.ValidationErrors = append(out.ValidationErrors, "usage: rbac-oracle --apply-reference MANIFEST.json REQUESTS.json")
	} else {
		manifest, e1 := os.ReadFile(args[0])
		requests, e2 := os.ReadFile(args[1])
		if e1 != nil {
			out.ValidationErrors = append(out.ValidationErrors, "manifest: "+e1.Error())
		}
		if e2 != nil {
			out.ValidationErrors = append(out.ValidationErrors, "requests: "+e2.Error())
		}
		if len(out.ValidationErrors) == 0 {
			out = evaluateApply(manifest, requests)
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

func isApplyOperation(op string) bool { return op == "apply-existing" || op == "apply-missing" }

// This catalogue bounds the reference input, not native RBAC's arbitrary-verb
// behavior. The legacy initial-authorization catalogue remains unchanged.
func applyRequestDomain(r applyRequest) error {
	if !r.ResourceRequest || r.ID == "" || r.Username == "" || r.Groups == nil {
		return fmt.Errorf("invalid identity/request marker")
	}
	seen := map[string]bool{}
	for _, g := range r.Groups {
		if g == "" || seen[g] {
			return fmt.Errorf("invalid identity groups")
		}
		seen[g] = true
	}
	namespaced := r.Resource != "nodes"
	base := (r.APIGroup == "" && sets.NewString("configmaps", "secrets", "pods", "services", "endpoints", "nodes").Has(r.Resource)) ||
		(r.APIGroup == "apps" && r.Resource == "deployments") || (r.APIGroup == "discovery.k8s.io" && r.Resource == "endpointslices")
	permitted := false
	if r.Subresource == "" && base {
		permitted = sets.NewString("get", "list", "watch", "update", "patch", "delete", "create", "deletecollection", "apply-existing", "apply-missing").Has(r.Operation)
	} else {
		verbs := ""
		switch r.APIGroup + "/" + r.Resource + "/" + r.Subresource {
		case "/pods/log":
			verbs = "get"
		case "/pods/exec":
			verbs = "get create"
		case "/serviceaccounts/token":
			verbs = "create"
		case "/pods/status", "/services/status", "/nodes/status", "apps/deployments/status", "apps/deployments/scale":
			verbs = "get update patch"
		}
		permitted = sets.NewString(strings.Fields(verbs)...).Has(r.Operation)
	}
	if !permitted {
		return fmt.Errorf("outside installed operation catalogue")
	}
	if namespaced {
		allNamespaces := r.Subresource == "" && (r.Operation == "list" || r.Operation == "watch") && r.Namespace == ""
		if !allNamespaces && (r.Namespace == "" || len(validation.IsDNS1123Label(r.Namespace)) != 0) {
			return fmt.Errorf("named namespace required")
		}
	} else if r.Namespace != "" {
		return fmt.Errorf("node namespace must be empty")
	}
	collection := r.Subresource == "" && (r.Operation == "create" || r.Operation == "deletecollection")
	if collection {
		if r.Name != "" {
			return fmt.Errorf("collection write name must be empty")
		}
	} else if r.Name != "" {
		if len(validation.IsDNS1123Subdomain(r.Name)) != 0 {
			return fmt.Errorf("invalid object name")
		}
	} else if r.Operation != "list" && r.Operation != "watch" {
		return fmt.Errorf("named target required")
	}
	return nil
}

func decodeApplyRequests(data []byte) ([]applyRequest, []string) {
	var raw []json.RawMessage
	if !json.Valid(data) || json.Unmarshal(data, &raw) != nil || raw == nil || len(raw) == 0 {
		return nil, []string{"requests: expected nonempty array"}
	}
	requests, errors := []applyRequest{}, []string{}
	seen := map[string]bool{}
	required := []string{"id", "username", "groups", "operation", "apiGroup", "resource", "namespace", "name", "subresource", "resourceRequest"}
	for i, entry := range raw {
		prefix := fmt.Sprintf("requests[%d]", i)
		var fields map[string]json.RawMessage
		var r applyRequest
		strictErrors, err := strictjson.UnmarshalStrict(entry, &r)
		if err != nil || json.Unmarshal(entry, &fields) != nil || fields == nil {
			errors = append(errors, prefix+": invalid request object")
			continue
		}
		for _, e := range strictErrors {
			errors = append(errors, prefix+": "+e.Error())
		}
		for _, f := range required {
			v, exists := fields[f]
			if !exists || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				errors = append(errors, prefix+"."+f+": required non-null field")
			}
		}
		if err := applyRequestDomain(r); err != nil {
			errors = append(errors, prefix+": "+err.Error())
		}
		if seen[r.ID] {
			errors = append(errors, prefix+": duplicate id")
		}
		seen[r.ID] = true
		requests = append(requests, r)
	}
	return requests, errors
}

type applyStrategy interface {
	rest.RESTCreateStrategy
	rest.RESTUpdateStrategy
}

func applyFixture(r applyRequest) (runtime.Object, []byte, schema.GroupVersionKind, applyStrategy, error) {
	var kind string
	var strategy applyStrategy
	body := map[string]interface{}{}
	switch r.APIGroup + "/" + r.Resource {
	case "/configmaps":
		kind, strategy = "ConfigMap", configmap.Strategy
	case "/secrets":
		kind, strategy = "Secret", secret.Strategy
	case "/pods":
		kind, strategy = "Pod", pod.Strategy
		body["spec"] = map[string]interface{}{"containers": []interface{}{map[string]interface{}{"name": "fixture", "image": "example.invalid/fixture:v1"}}}
	case "/services":
		kind, strategy = "Service", service.Strategy
		body["spec"] = map[string]interface{}{"type": "ExternalName", "externalName": "example.invalid"}
	case "/endpoints":
		kind, strategy = "Endpoints", endpoint.Strategy
	case "/nodes":
		kind, strategy = "Node", node.Strategy
	case "apps/deployments":
		kind, strategy = "Deployment", deployment.Strategy
		labels := map[string]interface{}{"app": "fixture"}
		body["spec"] = map[string]interface{}{"selector": map[string]interface{}{"matchLabels": labels}, "template": map[string]interface{}{
			"metadata": map[string]interface{}{"labels": labels}, "spec": map[string]interface{}{"containers": []interface{}{map[string]interface{}{"name": "fixture", "image": "example.invalid/fixture:v1"}}}}}
	case "discovery.k8s.io/endpointslices":
		kind, strategy = "EndpointSlice", endpointslice.Strategy
		body["addressType"], body["endpoints"], body["ports"] = "IPv4", []interface{}{}, []interface{}{}
	default:
		return nil, nil, schema.GroupVersionKind{}, nil, fmt.Errorf("not an SSA base resource")
	}
	gvk := schema.GroupVersionKind{Group: r.APIGroup, Version: "v1", Kind: kind}
	body["apiVersion"], body["kind"] = gvk.GroupVersion().String(), kind
	metadata := map[string]interface{}{"name": r.Name}
	if r.Namespace != "" {
		metadata["namespace"] = r.Namespace
	}
	body["metadata"] = metadata
	data, err := json.Marshal(body)
	if err != nil {
		return nil, nil, gvk, nil, err
	}
	obj, _, err := legacyscheme.Codecs.UniversalDecoder(schema.GroupVersion{Group: r.APIGroup, Version: runtime.APIVersionInternal}).Decode(data, nil, nil)
	if err != nil {
		return nil, nil, gvk, nil, err
	}
	return obj, data, gvk, strategy, nil
}

// All unimplemented storage methods panic through the nil embedded interface:
// accidental writes or network-backed storage use cannot silently pass.
type applyMemoryStorage struct {
	storage.Interface
	current runtime.Object
	reads   int
}

func (s *applyMemoryStorage) Versioner() storage.Versioner { return storage.APIObjectVersioner{} }
func (s *applyMemoryStorage) Get(_ context.Context, key string, opts storage.GetOptions, out runtime.Object) error {
	s.reads++
	if s.current == nil {
		if !opts.IgnoreNotFound {
			return storage.NewKeyNotFoundError(key, 0)
		}
		return nil
	}
	reflect.ValueOf(out).Elem().Set(reflect.ValueOf(s.current.DeepCopyObject()).Elem())
	return nil
}

type applyRecordingAuthorizer struct {
	inner  authorizer.Authorizer
	stages []applyStage
}

func decisionName(d authorizer.Decision) string {
	switch d {
	case authorizer.DecisionAllow:
		return "Allow"
	case authorizer.DecisionNoOpinion:
		return "NoOpinion"
	case authorizer.DecisionDeny:
		return "Deny"
	default:
		return "Invalid"
	}
}
func (a *applyRecordingAuthorizer) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	d, reason, err := a.inner.Authorize(ctx, attrs)
	groups := append([]string{}, attrs.GetUser().GetGroups()...)
	stage := applyStage{Attributes: urlAttributes{Username: attrs.GetUser().GetName(), Groups: groups, Verb: attrs.GetVerb(),
		APIGroup: attrs.GetAPIGroup(), APIVersion: attrs.GetAPIVersion(), Resource: attrs.GetResource(), Subresource: attrs.GetSubresource(),
		Namespace: attrs.GetNamespace(), Name: attrs.GetName(), ResourceRequest: attrs.IsResourceRequest(), Path: attrs.GetPath()}, Decision: decisionName(d), Reason: reason}
	if err != nil {
		stage.Error = err.Error()
	}
	a.stages = append(a.stages, stage)
	return d, reason, err
}

// bodyOverride is test-only: production campaign inputs cannot change the
// valid fixture or smuggle a different existence state/body through JSON.
func runNativeApply(r applyRequest, auth authorizer.Authorizer, bodyOverride *string) (applyDecision, error) {
	row := applyDecision{decision: decision{ID: r.ID}, Stages: []applyStage{}}
	obj, body, kind, strategy, err := applyFixture(r)
	if err != nil {
		return row, err
	}
	memory := &applyMemoryStorage{}
	if r.Operation == "apply-existing" {
		memory.current = obj.DeepCopyObject()
		accessor, err := apimeta.Accessor(memory.current)
		if err != nil {
			return row, err
		}
		accessor.SetUID(types.UID("reference-existing-uid"))
		accessor.SetResourceVersion("1")
	}
	newObject := func() runtime.Object { return reflect.New(reflect.TypeOf(obj).Elem()).Interface().(runtime.Object) }
	resource := schema.GroupVersionResource{Group: r.APIGroup, Version: "v1", Resource: r.Resource}
	codec := legacyscheme.Codecs.LegacyCodec(kind.GroupVersion())
	store := &registry.Store{NewFunc: newObject, DefaultQualifiedResource: resource.GroupResource(),
		SingularQualifiedResource: resource.GroupResource(), CreateStrategy: strategy, UpdateStrategy: strategy,
		KeyRootFunc: func(context.Context) string { return "/fixtures" },
		KeyFunc:     func(_ context.Context, name string) (string, error) { return "/fixtures/" + name, nil },
		ObjectNameFunc: func(o runtime.Object) (string, error) {
			a, e := apimeta.Accessor(o)
			if e != nil {
				return "", e
			}
			return a.GetName(), nil
		},
		Storage: registry.DryRunnableStorage{Storage: memory, Codec: codec}}
	fm, err := managedfields.NewDefaultFieldManager(managedfields.NewDeducedTypeConverter(), legacyscheme.Scheme,
		legacyscheme.Scheme, legacyscheme.Scheme, kind, schema.GroupVersion{Group: r.APIGroup, Version: runtime.APIVersionInternal}, "", nil)
	if err != nil {
		return row, err
	}
	recorded := &applyRecordingAuthorizer{inner: auth, stages: []applyStage{}}
	scope := &handlers.RequestScope{Namer: handlers.ContextBasedNaming{Namer: apimeta.NewAccessor()},
		Serializer: legacyscheme.Codecs, ParameterCodec: legacyscheme.ParameterCodec, Creater: legacyscheme.Scheme,
		Convertor: legacyscheme.Scheme, Defaulter: legacyscheme.Scheme, Typer: legacyscheme.Scheme,
		UnsafeConvertor: runtime.UnsafeObjectConvertor(legacyscheme.Scheme), Authorizer: recorded, FieldManager: fm,
		Resource: resource, Kind: kind, MetaGroupVersion: metav1.SchemeGroupVersion,
		HubGroupVersion: schema.GroupVersion{Group: r.APIGroup, Version: runtime.APIVersionInternal}, MaxRequestBodyBytes: 1 << 20}
	patch := handlers.PatchResource(store, scope, nil, []string{string(types.ApplyPatchType)})
	entry := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { row.HandlerEntered = true; patch.ServeHTTP(w, req) })
	factory := &apirequest.RequestInfoFactory{APIPrefixes: sets.NewString("api", "apis"), GrouplessAPIPrefixes: sets.NewString("api")}
	handler := filters.WithRequestInfo(filters.WithAuthorization(entry, recorded, legacyscheme.Codecs), factory)
	path := "/api/v1"
	if r.APIGroup != "" {
		path = "/apis/" + r.APIGroup + "/v1"
	}
	if r.Namespace != "" {
		path += "/namespaces/" + r.Namespace
	}
	path += "/" + r.Resource + "/" + r.Name
	if bodyOverride != nil {
		body = []byte(*bodyOverride)
	}
	// Force isolates authorization from fixture field-ownership conflicts;
	// field ownership and API effects are explicitly outside this campaign.
	req := httptest.NewRequest(http.MethodPatch, path+"?fieldManager=soundcheck-reference&dryRun=All&force=true", bytes.NewReader(body))
	req.Header.Set("Content-Type", string(types.ApplyPatchType))
	req.Header.Set("Accept", "application/json")
	req = req.WithContext(apirequest.WithUser(audit.WithAuditContext(req.Context()), &user.DefaultInfo{Name: r.Username, Groups: r.Groups}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	row.Stages, row.HTTPStatus, row.StorageReads = recorded.stages, response.Code, memory.reads
	row.Decision = "NoOpinion"
	if response.Code == http.StatusOK || response.Code == http.StatusCreated {
		row.Decision = "Allow"
	}
	if response.Code != http.StatusOK && response.Code != http.StatusCreated && response.Code != http.StatusForbidden {
		return row, fmt.Errorf("native handler returned %d: %s", response.Code, response.Body.String())
	}
	return row, nil
}

func evaluateApply(manifestJSON, requestsJSON []byte) applyResult {
	out := emptyApplyResult()
	objects, manifestErrors := decodeManifest(manifestJSON)
	requests, requestErrors := decodeApplyRequests(requestsJSON)
	out.ValidationErrors = append(out.ValidationErrors, manifestErrors...)
	out.ValidationErrors = append(out.ValidationErrors, requestErrors...)
	if len(out.ValidationErrors) > 0 {
		return out
	}
	_, static := rbacresolver.NewTestRuleResolver(objects.roles, objects.roleBindings, objects.clusterRoles, objects.clusterRoleBindings)
	rbac := rbacauthorizer.New(static, static, static, static)
	for _, req := range requests {
		var row applyDecision
		if isApplyOperation(req.Operation) {
			var err error
			row, err = runNativeApply(req, rbac, nil)
			if err != nil {
				out.ValidationErrors = append(out.ValidationErrors, req.ID+": "+err.Error())
				continue
			}
		} else {
			recorded := &applyRecordingAuthorizer{inner: rbac, stages: []applyStage{}}
			d, reason, err := recorded.Authorize(context.Background(), authorizer.AttributesRecord{
				User: &user.DefaultInfo{Name: req.Username, Groups: req.Groups}, Verb: req.Operation, APIGroup: req.APIGroup,
				APIVersion: "v1", Resource: req.Resource, Subresource: req.Subresource, Namespace: req.Namespace, Name: req.Name, ResourceRequest: true})
			row = applyDecision{decision: decision{ID: req.ID, Decision: decisionName(d), Reason: reason}, Stages: recorded.stages}
			if err != nil {
				row.Error = err.Error()
			}
		}
		out.Decisions = append(out.Decisions, row)
	}
	if len(out.ValidationErrors) > 0 {
		out.Decisions = []applyDecision{}
		return out
	}
	out.Valid = true
	return out
}
