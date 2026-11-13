package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func coverageURLInput(method, path string) []byte {
	data, _ := json.Marshal([]urlRequest{{ID: "request", Username: "alice", Groups: []string{}, Method: method, URL: path}})
	return data
}

func TestCoverageNamespacesHaveEndpointSpecificAttributes(t *testing.T) {
	role := `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"reader","namespace":"demo"},"rules":[{"verbs":["*"],"apiGroups":[""],"resources":["namespaces","namespaces/status"]}]}`
	for _, tc := range []struct{ method, path, verb, namespace, name, subresource, want string }{
		{"GET", "/api/v1/namespaces/demo", "get", "demo", "demo", "", "Allow"},
		{"PUT", "/api/v1/namespaces/demo", "update", "demo", "demo", "", "Allow"},
		{"PATCH", "/api/v1/namespaces/demo", "patch", "demo", "demo", "", "Allow"},
		{"DELETE", "/api/v1/namespaces/demo", "delete", "demo", "demo", "", "Allow"},
		{"GET", "/api/v1/namespaces/other", "get", "other", "other", "", "NoOpinion"},
		{"GET", "/api/v1/namespaces", "list", "", "", "", "NoOpinion"},
		{"GET", "/api/v1/namespaces?fieldSelector=metadata.name%3Ddemo", "list", "", "demo", "", "NoOpinion"},
		{"GET", "/api/v1/namespaces?watch=true&fieldSelector=metadata.name%3Ddemo", "watch", "", "demo", "", "NoOpinion"},
		{"GET", "/api/v1/watch/namespaces/demo", "watch", "demo", "demo", "", "Allow"},
		{"POST", "/api/v1/namespaces", "create", "", "", "", "NoOpinion"},
		{"DELETE", "/api/v1/namespaces?fieldSelector=metadata.name%3Ddemo", "deletecollection", "", "", "", "NoOpinion"},
		{"GET", "/api/v1/namespaces/demo/status", "get", "demo", "demo", "status", "Allow"},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			out := evaluateCoverageURLs(manifest(role, binding), coverageURLInput(tc.method, tc.path))
			if !out.Valid || len(out.Decisions) != 1 {
				t.Fatalf("native projection failed: %+v", out)
			}
			row, a := out.Decisions[0], out.Decisions[0].Attributes
			if row.Decision != tc.want || a.Verb != tc.verb || a.Namespace != tc.namespace || a.Name != tc.name || a.Subresource != tc.subresource || a.Resource != "namespaces" || a.APIGroup != "" || a.APIVersion != "v1" || !a.ResourceRequest || row.Error != "" {
				t.Fatalf("namespace endpoint differs from pinned expectation: %+v", row)
			}
		})
	}
}

func TestCoverageNativeNonresourceClassification(t *testing.T) {
	urlRole := `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"reader"},"rules":[{"verbs":["*"],"nonResourceURLs":["*"]}]}`
	bind := `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"reader"},"roleRef":{"kind":"ClusterRole","name":"reader","apiGroup":"rbac.authorization.k8s.io"},"subjects":[{"kind":"User","name":"alice","apiGroup":"rbac.authorization.k8s.io"}]}`
	for _, tc := range []struct {
		method, path, verb, group, version, resource string
		isResource                                   bool
	}{
		{"GET", "/", "get", "", "", "", false},
		{"HEAD", "/readyz", "head", "", "", "", false},
		{"GET", "/api/v1", "get", "", "", "", false},
		{"GET", "/api/v1/", "get", "", "", "", false},
		{"GET", "/apis/apps/v1", "get", "", "", "", false},
		{"GET", "/api/v1/pods", "list", "", "v1", "pods", true},
		{"HEAD", "/api/v1/pods", "list", "", "v1", "pods", true},
		{"GET", "/apis/apps/v1/deployments", "list", "apps", "v1", "deployments", true},
		{"GET", "/openapi/v3/apis/apps/v1?hash=fixture", "get", "", "", "", false},
		{"POST", "/metrics", "post", "", "", "", false},
		{"OPTIONS", "/healthz", "options", "", "", "", false},
		{"GET", "/apis/widgets.example.test/v1/widgets", "list", "widgets.example.test", "v1", "widgets", true},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			out := evaluateCoverageURLs(manifest(urlRole, bind), coverageURLInput(tc.method, tc.path))
			if !out.Valid || len(out.Decisions) != 1 {
				t.Fatalf("native projection: %+v", out)
			}
			row, a := out.Decisions[0], out.Decisions[0].Attributes
			want := "Allow"
			if tc.isResource {
				want = "NoOpinion"
			}
			if row.Decision != want || a.ResourceRequest != tc.isResource || a.Verb != tc.verb || a.APIGroup != tc.group || a.APIVersion != tc.version || a.Resource != tc.resource || row.Error != "" {
				t.Fatalf("native classification/URL separation: %+v", row)
			}
		})
	}
	// Namespaced bindings never supply nonresource grants, even for a valid
	// ClusterRole containing those rules.
	localBind := strings.Replace(strings.Replace(bind, `"kind":"ClusterRoleBinding"`, `"kind":"RoleBinding"`, 1), `"metadata":{"name":"reader"}`, `"metadata":{"name":"reader","namespace":"demo"}`, 1)
	out := evaluateCoverageURLs(manifest(urlRole, localBind), coverageURLInput("GET", "/readyz"))
	if !out.Valid || out.Decisions[0].Decision != "NoOpinion" {
		t.Fatalf("local URL grant: %+v", out)
	}
}

func TestCoverageCustomNamespacedAndClusterRoutes(t *testing.T) {
	role := `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"reader","namespace":"demo"},"rules":[{"verbs":["*"],"apiGroups":["widgets.example.test"],"resources":["widgets","clusterwidgets"]}]}`
	for _, tc := range []struct{ path, namespace, name, resource, want string }{
		{"/apis/widgets.example.test/v1/namespaces/demo/widgets/item", "demo", "item", "widgets", "Allow"},
		{"/apis/widgets.example.test/v1/namespaces/other/widgets/item", "other", "item", "widgets", "NoOpinion"},
		{"/apis/widgets.example.test/v1/widgets", "", "", "widgets", "NoOpinion"},
		{"/apis/widgets.example.test/v1/clusterwidgets/item", "", "item", "clusterwidgets", "NoOpinion"},
	} {
		out := evaluateCoverageURLs(manifest(role, binding), coverageURLInput("GET", tc.path))
		if !out.Valid || len(out.Decisions) != 1 {
			t.Fatalf("custom route: %+v", out)
		}
		a := out.Decisions[0].Attributes
		if out.Decisions[0].Decision != tc.want || a.APIGroup != "widgets.example.test" || a.Resource != tc.resource || a.Namespace != tc.namespace || a.Name != tc.name {
			t.Fatalf("custom namespace attributes: %+v", out)
		}
	}
}
