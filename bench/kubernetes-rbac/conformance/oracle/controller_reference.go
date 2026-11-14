// Controller API acceptance exercises the pinned API installer, request filter,
// RBAC authorizer and real review REST handlers. No cluster or storage is used.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/emicklei/go-restful/v3"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsinstall "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	crdregistry "k8s.io/apiextensions-apiserver/pkg/registry/customresourcedefinition"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints"
	"k8s.io/apiserver/pkg/endpoints/filters"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	registry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	admissionregistration "k8s.io/kubernetes/pkg/apis/admissionregistration"
	admissioninstall "k8s.io/kubernetes/pkg/apis/admissionregistration/install"
	authenticationinstall "k8s.io/kubernetes/pkg/apis/authentication/install"
	authorizationinstall "k8s.io/kubernetes/pkg/apis/authorization/install"
	mutating "k8s.io/kubernetes/pkg/registry/admissionregistration/mutatingwebhookconfiguration"
	mutatingstorage "k8s.io/kubernetes/pkg/registry/admissionregistration/mutatingwebhookconfiguration/storage"
	validating "k8s.io/kubernetes/pkg/registry/admissionregistration/validatingwebhookconfiguration"
	validatingstorage "k8s.io/kubernetes/pkg/registry/admissionregistration/validatingwebhookconfiguration/storage"
	"k8s.io/kubernetes/pkg/registry/authentication/tokenreview"
	"k8s.io/kubernetes/pkg/registry/authorization/subjectaccessreview"
	rbacresolver "k8s.io/kubernetes/pkg/registry/rbac/validation"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
)

func controllerScheme() *kruntime.Scheme {
	scheme := kruntime.NewScheme()
	metav1.AddToGroupVersion(scheme, metav1.SchemeGroupVersion)
	admissioninstall.Install(scheme)
	authorizationinstall.Install(scheme)
	authenticationinstall.Install(scheme)
	apiextensionsinstall.Install(scheme)
	return scheme
}

// Construct the native storage types with their native strategies. The fixture
// stores supply object factories for discovery only; no storage method executes.
func controllerStorages(scheme *kruntime.Scheme) map[string]map[string]rest.Storage {
	validatingStore := &registry.Store{
		NewFunc:        func() kruntime.Object { return &admissionregistration.ValidatingWebhookConfiguration{} },
		NewListFunc:    func() kruntime.Object { return &admissionregistration.ValidatingWebhookConfigurationList{} },
		CreateStrategy: validating.Strategy, UpdateStrategy: validating.Strategy, DeleteStrategy: validating.Strategy,
	}
	mutatingStore := &registry.Store{
		NewFunc:        func() kruntime.Object { return &admissionregistration.MutatingWebhookConfiguration{} },
		NewListFunc:    func() kruntime.Object { return &admissionregistration.MutatingWebhookConfigurationList{} },
		CreateStrategy: mutating.Strategy, UpdateStrategy: mutating.Strategy, DeleteStrategy: mutating.Strategy,
	}
	crdStrategy := crdregistry.NewStrategy(scheme)
	crdStore := &registry.Store{
		NewFunc:        func() kruntime.Object { return &apiextensions.CustomResourceDefinition{} },
		NewListFunc:    func() kruntime.Object { return &apiextensions.CustomResourceDefinitionList{} },
		CreateStrategy: crdStrategy, UpdateStrategy: crdStrategy, DeleteStrategy: crdStrategy, ResetFieldsStrategy: crdStrategy,
	}
	crdREST := &crdregistry.REST{Store: crdStore}
	return map[string]map[string]rest.Storage{
		"admissionregistration.k8s.io": {
			"validatingwebhookconfigurations": &validatingstorage.REST{Store: validatingStore},
			"mutatingwebhookconfigurations":   &mutatingstorage.REST{Store: mutatingStore},
		},
		"apiextensions.k8s.io":  {"customresourcedefinitions": crdREST, "customresourcedefinitions/status": crdregistry.NewStatusREST(scheme, crdREST)},
		"authorization.k8s.io":  {"subjectaccessreviews": subjectaccessreview.NewREST(nil)},
		"authentication.k8s.io": {"tokenreviews": tokenreview.NewREST(nil, nil)},
	}
}

func controllerGroup(scheme *kruntime.Scheme, group string, storage map[string]rest.Storage) *endpoints.APIGroupVersion {
	return &endpoints.APIGroupVersion{
		Root: "/apis", GroupVersion: schema.GroupVersion{Group: group, Version: "v1"},
		Storage: storage, OptionsExternalVersion: &metav1.SchemeGroupVersion,
		Creater: scheme, Convertor: scheme, Defaulter: scheme, Typer: scheme,
		UnsafeConvertor: kruntime.UnsafeObjectConvertor(scheme), Namer: apimeta.NewAccessor(),
		TypeConverter:              managedfields.NewDeducedTypeConverter(),
		EquivalentResourceRegistry: kruntime.NewEquivalentResourceRegistry(),
		ParameterCodec:             kruntime.NewParameterCodec(scheme), Serializer: serializer.NewCodecFactory(scheme),
	}
}

func controllerRuntimeInfo() (map[string]interface{}, error) {
	scheme := controllerScheme()
	container := restful.NewContainer()
	discovery := map[string]interface{}{}
	for group, storage := range controllerStorages(scheme) {
		resources, _, err := controllerGroup(scheme, group, storage).InstallREST(container)
		if err != nil {
			return nil, err
		}
		for _, resource := range resources {
			verbs := append([]string{}, resource.Verbs...)
			sort.Strings(verbs)
			discovery[resource.Resource+"."+group] = map[string]interface{}{"scope": resource.Scope, "verbs": verbs}
			for _, sub := range resource.Subresources {
				verbs := append([]string{}, sub.Verbs...)
				sort.Strings(verbs)
				discovery[resource.Resource+"/"+sub.Subresource+"."+group] = map[string]interface{}{"scope": resource.Scope, "verbs": verbs}
			}
		}
	}
	routes := []string{}
	for _, ws := range container.RegisteredWebServices() {
		for _, route := range ws.Routes() {
			routes = append(routes, route.Method+" "+route.Path)
		}
	}
	sort.Strings(routes)
	links := map[string]interface{}{}
	for name, function := range map[string]interface{}{
		"api-installer":                (*endpoints.APIGroupVersion).InstallREST,
		"request-info":                 filters.WithRequestInfo,
		"request-classifier":           (*apirequest.RequestInfoFactory).NewRequestInfo,
		"authorization-filter":         filters.WithAuthorization,
		"authorizer-attributes":        filters.GetAuthorizerAttributes,
		"rbac-authorizer":              (*rbacauthorizer.RBACAuthorizer).Authorize,
		"subject-access-review-create": (*subjectaccessreview.REST).Create,
		"token-review-create":          (*tokenreview.REST).Create,
	} {
		f := runtime.FuncForPC(reflect.ValueOf(function).Pointer())
		file, line := f.FileLine(f.Entry())
		links[name] = map[string]interface{}{"function": f.Name(), "file": file, "line": line}
	}
	base := applyRuntimeInfo()
	return map[string]interface{}{
		"schema_version": 1, "kind": "rbac_controller_native_linkage", "go_version": runtime.Version(),
		"modules": base["modules"], "functions": links, "discovery": discovery, "routes": routes,
		"allow_create_on_update": map[string]bool{
			"validatingwebhookconfigurations":  validating.Strategy.AllowCreateOnUpdate(),
			"mutatingwebhookconfigurations":    mutating.Strategy.AllowCreateOnUpdate(),
			"customresourcedefinitions":        crdregistry.NewStrategy(scheme).AllowCreateOnUpdate(),
			"customresourcedefinitions/status": crdregistry.NewStatusStrategy(scheme).AllowCreateOnUpdate(),
		},
	}, nil
}

type controllerReviewDecision struct {
	ID                 string          `json:"id"`
	Initial            string          `json:"initial"`
	Attributes         *urlAttributes  `json:"attributes"`
	StatusCode         int             `json:"status_code"`
	HandlerCalls       int             `json:"review_calls"`
	ReviewAttributes   *urlAttributes  `json:"review_attributes"`
	AuthenticatedToken string          `json:"authenticated_token"`
	Response           json.RawMessage `json:"response"`
}

type controllerReviewResult struct {
	SchemaVersion    int                        `json:"schema_version"`
	Kind             string                     `json:"kind"`
	Valid            bool                       `json:"valid"`
	ValidationErrors []string                   `json:"validation_errors"`
	Decisions        []controllerReviewDecision `json:"decisions"`
}

func controllerAttributes(attrs authorizer.Attributes) *urlAttributes {
	return &urlAttributes{Username: attrs.GetUser().GetName(), Groups: append([]string{}, attrs.GetUser().GetGroups()...),
		Verb: attrs.GetVerb(), APIGroup: attrs.GetAPIGroup(), APIVersion: attrs.GetAPIVersion(), Resource: attrs.GetResource(),
		Subresource: attrs.GetSubresource(), Namespace: attrs.GetNamespace(), Name: attrs.GetName(),
		ResourceRequest: attrs.IsResourceRequest(), Path: attrs.GetPath()}
}

func evaluateControllerReviews(manifestJSON, requestJSON []byte) controllerReviewResult {
	out := controllerReviewResult{SchemaVersion: 1, Kind: "rbac_controller_review_authorization", ValidationErrors: []string{}, Decisions: []controllerReviewDecision{}}
	objects, errors := decodeManifest(manifestJSON)
	out.ValidationErrors = append(out.ValidationErrors, errors...)
	requests, errors := decodeURLRequests(requestJSON)
	out.ValidationErrors = append(out.ValidationErrors, errors...)
	if len(out.ValidationErrors) != 0 {
		return out
	}
	_, rules := rbacresolver.NewTestRuleResolver(objects.roles, objects.roleBindings, objects.clusterRoles, objects.clusterRoleBindings)
	rbac := rbacauthorizer.New(rules, rules, rules, rules)
	scheme := controllerScheme()
	for _, input := range requests {
		row := controllerReviewDecision{ID: input.ID}
		// These deterministic stand-ins are only the reviewed authorization or
		// authentication service. The initial caller check is the native RBAC
		// implementation and the API handlers are unmodified Kubernetes code.
		reviewAuth := authorizer.AuthorizerFunc(func(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
			row.HandlerCalls++
			row.ReviewAttributes = controllerAttributes(attrs)
			if attrs.GetUser().GetName() == "reviewed-allowed" {
				return authorizer.DecisionAllow, "fixture reviewed subject allowed", nil
			}
			return authorizer.DecisionDeny, "fixture reviewed subject denied", nil
		})
		tokenAuth := authenticator.RequestFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
			row.HandlerCalls++
			row.AuthenticatedToken = strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
			if row.AuthenticatedToken != "fixture-valid-token" {
				return nil, false, nil
			}
			return &authenticator.Response{User: &user.DefaultInfo{Name: "reviewed-token-user", Groups: []string{"reviewed-token-group"}}}, true, nil
		})
		group, resource := "", ""
		var storage rest.Storage
		switch input.URL {
		case "/apis/authorization.k8s.io/v1/subjectaccessreviews":
			group, resource, storage = "authorization.k8s.io", "subjectaccessreviews", subjectaccessreview.NewREST(reviewAuth)
		case "/apis/authentication.k8s.io/v1/tokenreviews":
			group, resource, storage = "authentication.k8s.io", "tokenreviews", tokenreview.NewREST(tokenAuth, nil)
		default:
			out.ValidationErrors = append(out.ValidationErrors, input.ID+": outside the fixed review endpoints")
			continue
		}
		container := restful.NewContainer()
		if _, _, err := controllerGroup(scheme, group, map[string]rest.Storage{resource: storage}).InstallREST(container); err != nil {
			out.ValidationErrors = append(out.ValidationErrors, input.ID+": "+err.Error())
			continue
		}
		initial := authorizer.AuthorizerFunc(func(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
			row.Attributes = controllerAttributes(attrs)
			decision, reason, err := rbac.Authorize(ctx, attrs)
			row.Initial = decisionName(decision)
			return decision, reason, err
		})
		factory := &apirequest.RequestInfoFactory{APIPrefixes: sets.NewString("api", "apis"), GrouplessAPIPrefixes: sets.NewString("api")}
		handler := filters.WithRequestInfo(filters.WithAuthorization(container, initial, serializer.NewCodecFactory(scheme)), factory)
		req := httptest.NewRequest(input.Method, input.URL, strings.NewReader(input.Body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(apirequest.WithUser(req.Context(), &user.DefaultInfo{Name: input.Username, Groups: input.Groups}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		row.StatusCode, row.Response = response.Code, append([]byte{}, response.Body.Bytes()...)
		if !json.Valid(row.Response) {
			out.ValidationErrors = append(out.ValidationErrors, input.ID+": invalid native JSON response")
		}
		out.Decisions = append(out.Decisions, row)
	}
	out.Valid = len(out.ValidationErrors) == 0
	return out
}

func controllerReviewFiles(args []string) {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: --controller-review-reference MANIFEST.json REQUESTS.json")
		os.Exit(2)
	}
	manifest, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	requests, err := os.ReadFile(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	out := evaluateControllerReviews(manifest, requests)
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if !out.Valid {
		os.Exit(1)
	}
}
