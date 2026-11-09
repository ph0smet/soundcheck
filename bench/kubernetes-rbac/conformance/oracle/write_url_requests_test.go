package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// RequestInfoFactory's v0.34.0 method mapping and deletecollection rewrite are
// upstream semantics, not this adapter's implementation. Query selectors only
// supply an effective Name in the existing collection get/list/watch branch.
func TestNamedWriteRequestInfo(t *testing.T) {
	writeRole := strings.Replace(readRole, `["get","list","watch"]`, `["update","patch","delete"]`, 1)
	for _, tc := range []struct {
		name, method, target, verb, namespace, objectName, subresource, want string
		selectorError                                                        bool
	}{
		{"put is update", "PUT", "/api/v1/namespaces/demo/secrets/token", "update", "demo", "token", "", "Allow", false},
		{"patch is distinct", "PATCH", "/api/v1/namespaces/demo/secrets/token", "patch", "demo", "token", "", "Allow", false},
		{"named delete", "DELETE", "/api/v1/namespaces/demo/secrets/token", "delete", "demo", "token", "", "Allow", false},
		{"write query cannot override name", "PATCH", "/api/v1/namespaces/demo/secrets/other?fieldSelector=metadata.name%3Dtoken&watch=true", "patch", "demo", "other", "", "NoOpinion", false},
		{"dry run still requires update", "PUT", "/api/v1/namespaces/demo/secrets/token?dryRun=All", "update", "demo", "token", "", "Allow", false},
		{"force apply query still patch", "PATCH", "/api/v1/namespaces/demo/secrets/token?fieldManager=manager&force=true", "patch", "demo", "token", "", "Allow", false},
		{"named write ignores invalid selector", "DELETE", "/api/v1/namespaces/demo/secrets/token?fieldSelector=broken", "delete", "demo", "token", "", "Allow", false},
		{"unnamed put remains unnamed update", "PUT", "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.name%3Dtoken", "update", "demo", "", "", "NoOpinion", false},
		{"unnamed patch remains unnamed patch", "PATCH", "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.name%3Dtoken", "patch", "demo", "", "", "NoOpinion", false},
		{"collection delete", "DELETE", "/api/v1/namespaces/demo/secrets", "deletecollection", "demo", "", "", "NoOpinion", false},
		{"selected collection deletion stays unnamed", "DELETE", "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.name%3Dtoken", "deletecollection", "demo", "", "", "NoOpinion", false},
		{"collection deletion retains selector error", "DELETE", "/api/v1/namespaces/demo/secrets?fieldSelector=broken", "deletecollection", "demo", "", "", "NoOpinion", true},
		{"post stays create", "POST", "/api/v1/namespaces/demo/secrets", "create", "demo", "", "", "NoOpinion", false},
		{"all namespace deletecollection", "DELETE", "/api/v1/secrets", "deletecollection", "", "", "", "NoOpinion", false},
		{"no invented namespace", "PATCH", "/api/v1/secrets/token", "patch", "", "token", "", "NoOpinion", false},
		{"subresource remains distinct", "PATCH", "/api/v1/namespaces/demo/secrets/token/status", "patch", "demo", "token", "status", "NoOpinion", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, err := json.Marshal([]urlRequest{{ID: "write", Username: "alice", Groups: []string{}, Method: tc.method, URL: tc.target}})
			if err != nil {
				t.Fatal(err)
			}
			out := evaluateURLs(manifest(writeRole, binding), input)
			if !out.Valid || len(out.Decisions) != 1 {
				t.Fatalf("upstream extraction failed: %+v", out)
			}
			row := out.Decisions[0]
			a := row.Attributes
			if a.Verb != tc.verb || a.Namespace != tc.namespace || a.Name != tc.objectName ||
				a.Subresource != tc.subresource || a.Resource != "secrets" || a.APIGroup != "" ||
				a.APIVersion != "v1" || !a.ResourceRequest || row.Decision != tc.want || row.Error != "" ||
				row.FieldSelectorError != tc.selectorError || row.LabelSelectorError {
				t.Fatalf("unexpected write authorization attributes: %+v", row)
			}
		})
	}
}

func TestWriteVerbsAndResourceNamesAreLiteral(t *testing.T) {
	for _, verb := range []string{"update", "patch", "delete"} {
		for _, method := range []string{"PUT", "PATCH", "DELETE"} {
			for _, names := range []string{`["token"]`, `["*"]`, `[""]`, `[]`} {
				policy := strings.Replace(readRole, `["get","list","watch"]`, `["`+verb+`"]`, 1)
				policy = strings.Replace(policy, `["token"]`, names, 1)
				input, _ := json.Marshal([]urlRequest{{ID: "write", Username: "alice", Groups: []string{},
					Method: method, URL: "/api/v1/namespaces/demo/secrets/token"}})
				out := evaluateURLs(manifest(policy, binding), input)
				wanted := "NoOpinion"
				if map[string]string{"PUT": "update", "PATCH": "patch", "DELETE": "delete"}[method] == verb &&
					(names == `["token"]` || names == `[]`) {
					wanted = "Allow"
				}
				if !out.Valid || len(out.Decisions) != 1 || out.Decisions[0].Decision != wanted {
					t.Fatalf("verb %s method %s resourceNames %s: %+v", verb, method, names, out)
				}
			}
		}
	}
}
