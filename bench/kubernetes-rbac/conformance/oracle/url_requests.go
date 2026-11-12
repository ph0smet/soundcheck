// This mode exercises the pinned API server's actual request-to-authorization
// boundary. It does not send HTTP or assert that a resource route exists, that
// storage accepts a selector, or that a full authorization chain permits it.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	rbacresolver "k8s.io/kubernetes/pkg/registry/rbac/validation"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
	strictjson "sigs.k8s.io/json"
)

type urlRequest struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
	Method   string   `json:"method"`
	URL      string   `json:"url"`
	Body     string   `json:"body,omitempty"`
}

// Every field is explicit: empty name and namespace have authorization meaning.
type urlAttributes struct {
	Username        string   `json:"username"`
	Groups          []string `json:"groups"`
	Verb            string   `json:"verb"`
	APIGroup        string   `json:"apiGroup"`
	APIVersion      string   `json:"apiVersion"`
	Resource        string   `json:"resource"`
	Namespace       string   `json:"namespace"`
	Name            string   `json:"name"`
	Subresource     string   `json:"subresource"`
	ResourceRequest bool     `json:"resourceRequest"`
	Path            string   `json:"path"`
}

type urlDecision struct {
	decision
	Attributes         urlAttributes `json:"attributes"`
	FieldSelectorError bool          `json:"field_selector_error"`
	LabelSelectorError bool          `json:"label_selector_error"`
}

type urlResult struct {
	SchemaVersion    int           `json:"schema_version"`
	Kind             string        `json:"kind"`
	Valid            bool          `json:"valid"`
	ValidationErrors []string      `json:"validation_errors"`
	Decisions        []urlDecision `json:"decisions"`
}

func emptyURLResult() urlResult {
	return urlResult{SchemaVersion: 1, Kind: "rbac_request_url_authorization",
		ValidationErrors: []string{}, Decisions: []urlDecision{}}
}

func requestURLFiles(args []string) {
	out := emptyURLResult()
	code := 2
	if len(args) != 2 {
		out.ValidationErrors = append(out.ValidationErrors, "usage: rbac-oracle --request-urls MANIFEST.json URL_REQUESTS.json")
	} else {
		manifest, manifestErr := os.ReadFile(args[0])
		requests, requestsErr := os.ReadFile(args[1])
		if manifestErr != nil {
			out.ValidationErrors = append(out.ValidationErrors, "manifest: "+manifestErr.Error())
		}
		if requestsErr != nil {
			out.ValidationErrors = append(out.ValidationErrors, "requests: "+requestsErr.Error())
		}
		if len(out.ValidationErrors) == 0 {
			out = evaluateURLs(manifest, requests)
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

func decodeURLRequests(data []byte) ([]urlRequest, []string) {
	errors := []string{}
	var raw []json.RawMessage
	if !json.Valid(data) || json.Unmarshal(data, &raw) != nil || raw == nil || len(raw) == 0 {
		return nil, []string{"requests: expected one nonempty JSON array"}
	}
	requests := []urlRequest{}
	seen := map[string]bool{}
	for i, entry := range raw {
		prefix := fmt.Sprintf("requests[%d]", i)
		var fields map[string]json.RawMessage
		var req urlRequest
		strictErrors, err := strictjson.UnmarshalStrict(entry, &req)
		if err != nil || json.Unmarshal(entry, &fields) != nil || fields == nil {
			errors = append(errors, prefix+": expected a request object with string fields and string-array groups")
			continue
		}
		for _, err := range strictErrors {
			errors = append(errors, prefix+": "+err.Error())
		}
		for _, field := range []string{"id", "username", "groups", "method", "url"} {
			value, exists := fields[field]
			if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				errors = append(errors, prefix+"."+field+": required non-null field")
			}
		}
		if body, exists := fields["body"]; exists && bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
			errors = append(errors, prefix+".body: must be a string when supplied")
		}
		if req.ID == "" || seen[req.ID] || req.Username == "" {
			errors = append(errors, prefix+": nonempty unique ID and nonempty username required")
		}
		seen[req.ID] = true
		groups := map[string]bool{}
		for _, group := range req.Groups {
			if group == "" || groups[group] {
				errors = append(errors, prefix+": groups must be unique nonempty strings")
			}
			groups[group] = true
		}
		// The harness observes origin-form request targets only; no network,
		// credentials, fragments, or URL normalization through a proxy.
		u, parseErr := url.ParseRequestURI(req.URL)
		if parseErr != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" ||
			!strings.HasPrefix(req.URL, "/") || strings.HasPrefix(req.URL, "//") || strings.Contains(req.URL, "#") {
			errors = append(errors, prefix+": url must be an origin-form request target")
		}
		if req.Method == "" || req.Method != strings.ToUpper(req.Method) {
			errors = append(errors, prefix+": method must be explicit uppercase HTTP method")
		}
		requests = append(requests, req)
	}
	return requests, errors
}

func evaluateURLs(manifestJSON, requestsJSON []byte) urlResult {
	out := emptyURLResult()
	objects, manifestErrors := decodeManifest(manifestJSON)
	requests, requestErrors := decodeURLRequests(requestsJSON)
	out.ValidationErrors = append(out.ValidationErrors, manifestErrors...)
	out.ValidationErrors = append(out.ValidationErrors, requestErrors...)
	if len(out.ValidationErrors) != 0 {
		return out
	}
	_, static := rbacresolver.NewTestRuleResolver(objects.roles, objects.roleBindings,
		objects.clusterRoles, objects.clusterRoleBindings)
	rbac := rbacauthorizer.New(static, static, static, static)
	factory := apirequest.RequestInfoFactory{APIPrefixes: sets.NewString("api", "apis"),
		GrouplessAPIPrefixes: sets.NewString("api")}
	for _, req := range requests {
		// A body is deliberately carried as raw text. RequestInfoFactory must
		// derive initial authorization attributes from the request target, not
		// infer an object name from metadata.name or metadata.generateName.
		httpRequest, err := http.NewRequest(req.Method, req.URL, strings.NewReader(req.Body))
		if err != nil {
			out.ValidationErrors = append(out.ValidationErrors, req.ID+": "+err.Error())
			continue
		}
		info, err := factory.NewRequestInfo(httpRequest)
		if err != nil {
			out.ValidationErrors = append(out.ValidationErrors, req.ID+": "+err.Error())
			continue
		}
		ctx := context.Background()
		// Copy the RequestInfo fields consumed by GetAuthorizerAttributes in
		// pinned apiserver v0.34.0/pkg/endpoints/filters/authorization.go.
		// Do not reimplement HTTP verb/name/namespace or selector extraction.
		// The filter package itself also pulls the API-server transport stack;
		// the reference harness needs only this value projection, not a server.
		attributes := authorizer.AttributesRecord{
			User:            &user.DefaultInfo{Name: req.Username, Groups: req.Groups},
			ResourceRequest: info.IsResourceRequest, Path: info.Path, Verb: info.Verb,
			APIGroup: info.APIGroup, APIVersion: info.APIVersion, Resource: info.Resource,
			Subresource: info.Subresource, Namespace: info.Namespace, Name: info.Name}
		// AuthorizeWithSelectors is locked on in v1.34.0. These parsing flags
		// are recorded as boundary evidence; the RBAC authorizer only matches
		// the effective Name already extracted by RequestInfoFactory.
		if info.FieldSelector != "" {
			selector, parseErr := fields.ParseSelector(info.FieldSelector)
			attributes.FieldSelectorParsingErr = parseErr
			if parseErr == nil {
				attributes.FieldSelectorRequirements = selector.Requirements()
			}
		}
		if info.LabelSelector != "" {
			selector, parseErr := labels.Parse(info.LabelSelector)
			attributes.LabelSelectorParsingErr = parseErr
			if parseErr == nil {
				attributes.LabelSelectorRequirements, _ = selector.Requirements()
			}
		}
		_, fieldErr := attributes.GetFieldSelector()
		_, labelErr := attributes.GetLabelSelector()
		verdict, reason, authErr := rbac.Authorize(ctx, attributes)
		row := urlDecision{decision: decision{ID: req.ID, Reason: reason},
			FieldSelectorError: fieldErr != nil, LabelSelectorError: labelErr != nil,
			Attributes: urlAttributes{Username: attributes.GetUser().GetName(), Groups: attributes.GetUser().GetGroups(),
				Verb: attributes.GetVerb(), APIGroup: attributes.GetAPIGroup(), APIVersion: attributes.GetAPIVersion(),
				Resource: attributes.GetResource(), Namespace: attributes.GetNamespace(), Name: attributes.GetName(),
				Subresource: attributes.GetSubresource(), ResourceRequest: attributes.IsResourceRequest(), Path: attributes.GetPath()}}
		switch verdict {
		case authorizer.DecisionAllow:
			row.Decision = "Allow"
		case authorizer.DecisionNoOpinion:
			row.Decision = "NoOpinion"
		case authorizer.DecisionDeny:
			row.Decision = "Deny"
		default:
			panic(fmt.Sprintf("unexpected upstream authorizer decision: %v", verdict))
		}
		if authErr != nil {
			row.Error = authErr.Error()
		}
		out.Decisions = append(out.Decisions, row)
	}
	if len(out.ValidationErrors) != 0 {
		out.Decisions = []urlDecision{}
		return out
	}
	out.Valid = true
	return out
}
