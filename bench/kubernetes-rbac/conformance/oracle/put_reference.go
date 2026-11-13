// PUT creation is selected by the native UpdateResource and generic store.
// Only the backing object's state is a fixture. Service allocation/admission,
// storage races and API success beyond this handler/store boundary are excluded.
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
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	rbacresolver "k8s.io/kubernetes/pkg/registry/rbac/validation"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
	strictjson "sigs.k8s.io/json"
)

func putRequestDomain(r applyRequest) error {
	if r.ID == "" || r.Username == "" || r.Groups == nil || !r.ResourceRequest {
		return fmt.Errorf("invalid identity/request marker")
	}
	seen := map[string]bool{}
	for _, group := range r.Groups {
		if group == "" || seen[group] {
			return fmt.Errorf("invalid identity groups")
		}
		seen[group] = true
	}
	if r.APIGroup != "" || (r.Resource != "services" && r.Resource != "endpoints") || r.Subresource != "" ||
		(r.Operation != "update-existing" && r.Operation != "update-missing") {
		return fmt.Errorf("outside installed PUT operation catalogue")
	}
	if r.Namespace == "" || len(validation.IsDNS1123Label(r.Namespace)) != 0 || r.Name == "" || len(validation.IsDNS1123Subdomain(r.Name)) != 0 {
		return fmt.Errorf("named namespace and target required")
	}
	return nil
}

func decodePutRequests(data []byte) ([]applyRequest, []string) {
	var raw []json.RawMessage
	if !json.Valid(data) || json.Unmarshal(data, &raw) != nil || raw == nil || len(raw) == 0 {
		return nil, []string{"requests: expected nonempty array"}
	}
	rows, errors := []applyRequest{}, []string{}
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
		if err := putRequestDomain(r); err != nil {
			errors = append(errors, prefix+": "+err.Error())
		}
		if seen[r.ID] {
			errors = append(errors, prefix+": duplicate id")
		}
		seen[r.ID] = true
		rows = append(rows, r)
	}
	return rows, errors
}

func putReferenceFiles(args []string) {
	out, code := emptyApplyResult(), 2
	out.Kind = "rbac_put_authorization"
	if len(args) != 2 {
		out.ValidationErrors = append(out.ValidationErrors, "usage: rbac-oracle --put-reference MANIFEST.json REQUESTS.json")
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
			out = evaluatePut(manifest, requests)
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

func evaluatePut(manifestJSON, requestsJSON []byte) applyResult {
	out := emptyApplyResult()
	out.Kind = "rbac_put_authorization"
	objects, manifestErrors := decodeManifest(manifestJSON)
	requests, requestErrors := decodePutRequests(requestsJSON)
	out.ValidationErrors = append(out.ValidationErrors, manifestErrors...)
	out.ValidationErrors = append(out.ValidationErrors, requestErrors...)
	if len(out.ValidationErrors) != 0 {
		return out
	}
	_, static := rbacresolver.NewTestRuleResolver(objects.roles, objects.roleBindings, objects.clusterRoles, objects.clusterRoleBindings)
	auth := rbacauthorizer.New(static, static, static, static)
	for _, r := range requests {
		row, err := runNativePut(r, auth, nil)
		if err != nil {
			out.ValidationErrors = append(out.ValidationErrors, r.ID+": "+err.Error())
			continue
		}
		out.Decisions = append(out.Decisions, row)
	}
	if len(out.ValidationErrors) != 0 {
		out.Decisions = []applyDecision{}
		return out
	}
	out.Valid = true
	return out
}

func runNativePut(r applyRequest, auth authorizer.Authorizer, bodyOverride *string) (applyDecision, error) {
	row := applyDecision{decision: decision{ID: r.ID}, Stages: []applyStage{}}
	obj, body, kind, strategy, err := applyFixture(r)
	if err != nil {
		return row, err
	}
	memory := &applyMemoryStorage{}
	if r.Operation == "update-existing" {
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
	update := handlers.UpdateResource(store, scope, nil)
	entry := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { row.HandlerEntered = true; update.ServeHTTP(w, req) })
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
	// Native UpdateResource decides whether its named-create callback is reached.
	// Dry-run executes native Store.Update without writing to a backing store.
	req := httptest.NewRequest(http.MethodPut, path+"?fieldManager=soundcheck-reference&dryRun=All", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
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
