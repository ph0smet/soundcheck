// Expanded coverage uses the linked native RequestInfo filter and
// GetAuthorizerAttributes. The reference does not infer route installation,
// object existence, or discovery from an RBAC rule or a request's body.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/filters"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	rbacresolver "k8s.io/kubernetes/pkg/registry/rbac/validation"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
)

func coverageURLFiles(args []string) {
	out := emptyURLResult()
	out.Kind = "rbac_coverage_url_authorization"
	code := 2
	if len(args) != 2 {
		out.ValidationErrors = append(out.ValidationErrors, "usage: rbac-oracle --coverage-urls MANIFEST.json URL_REQUESTS.json")
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
			out = evaluateCoverageURLs(manifest, requests)
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

func evaluateCoverageURLs(manifestJSON, requestsJSON []byte) urlResult {
	out := emptyURLResult()
	out.Kind = "rbac_coverage_url_authorization"
	objects, manifestErrors := decodeManifest(manifestJSON)
	requests, requestErrors := decodeURLRequests(requestsJSON)
	out.ValidationErrors = append(out.ValidationErrors, manifestErrors...)
	out.ValidationErrors = append(out.ValidationErrors, requestErrors...)
	if len(out.ValidationErrors) != 0 {
		return out
	}
	_, static := rbacresolver.NewTestRuleResolver(objects.roles, objects.roleBindings,
		objects.clusterRoles, objects.clusterRoleBindings)
	auth := rbacauthorizer.New(static, static, static, static)
	factory := &apirequest.RequestInfoFactory{APIPrefixes: sets.NewString("api", "apis"), GrouplessAPIPrefixes: sets.NewString("api")}
	for _, input := range requests {
		entered := false
		entry := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			entered = true
			attrs, err := filters.GetAuthorizerAttributes(req.Context())
			if err != nil {
				out.ValidationErrors = append(out.ValidationErrors, input.ID+": "+err.Error())
				return
			}
			d, reason, authErr := auth.Authorize(req.Context(), attrs)
			_, fieldErr := attrs.GetFieldSelector()
			_, labelErr := attrs.GetLabelSelector()
			row := urlDecision{decision: decision{ID: input.ID, Decision: decisionName(d), Reason: reason},
				FieldSelectorError: fieldErr != nil, LabelSelectorError: labelErr != nil,
				Attributes: urlAttributes{Username: attrs.GetUser().GetName(), Groups: append([]string{}, attrs.GetUser().GetGroups()...),
					Verb: attrs.GetVerb(), APIGroup: attrs.GetAPIGroup(), APIVersion: attrs.GetAPIVersion(),
					Resource: attrs.GetResource(), Namespace: attrs.GetNamespace(), Name: attrs.GetName(),
					Subresource: attrs.GetSubresource(), ResourceRequest: attrs.IsResourceRequest(), Path: attrs.GetPath()}}
			if authErr != nil {
				row.Error = authErr.Error()
			}
			out.Decisions = append(out.Decisions, row)
			w.WriteHeader(http.StatusNoContent)
		})
		req := httptest.NewRequest(input.Method, input.URL, strings.NewReader(input.Body))
		req = req.WithContext(apirequest.WithUser(req.Context(), &user.DefaultInfo{Name: input.Username, Groups: input.Groups}))
		response := httptest.NewRecorder()
		filters.WithRequestInfo(entry, factory).ServeHTTP(response, req)
		if !entered || response.Code != http.StatusNoContent {
			out.ValidationErrors = append(out.ValidationErrors, fmt.Sprintf("%s: native request projection failed (%d): %s", input.ID, response.Code, response.Body.String()))
		}
	}
	if len(out.ValidationErrors) != 0 {
		out.Decisions = []urlDecision{}
		return out
	}
	out.Valid = true
	return out
}
