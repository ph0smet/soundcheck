package main

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

var controllerBaseGroups = map[string]string{
	"validatingwebhookconfigurations": "admissionregistration.k8s.io",
	"mutatingwebhookconfigurations":   "admissionregistration.k8s.io",
	"customresourcedefinitions":       "apiextensions.k8s.io",
}

func TestControllerNativeInstalledVerbsAndScopes(t *testing.T) {
	info, err := controllerRuntimeInfo()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]interface{}{}
	for resource, group := range controllerBaseGroups {
		want[resource+"."+group] = map[string]interface{}{"scope": "Cluster", "verbs": []string{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"}}
	}
	want["customresourcedefinitions/status.apiextensions.k8s.io"] = map[string]interface{}{"scope": "Cluster", "verbs": []string{"get", "patch", "update"}}
	want["subjectaccessreviews.authorization.k8s.io"] = map[string]interface{}{"scope": "Cluster", "verbs": []string{"create"}}
	want["tokenreviews.authentication.k8s.io"] = map[string]interface{}{"scope": "Cluster", "verbs": []string{"create"}}
	a, _ := json.Marshal(info["discovery"])
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		t.Fatalf("native installer discovery differs:\n%s\nwant:\n%s", a, b)
	}
	for resource, allowed := range info["allow_create_on_update"].(map[string]bool) {
		if allowed {
			t.Fatalf("unexpected create-on-update: %s", resource)
		}
	}
	wantRoutes := []string{}
	for resource, group := range controllerBaseGroups {
		base := "/apis/" + group + "/v1/"
		wantRoutes = append(wantRoutes, "GET "+base+resource, "POST "+base+resource, "DELETE "+base+resource,
			"GET "+base+resource+"/{name}", "PUT "+base+resource+"/{name}", "PATCH "+base+resource+"/{name}", "DELETE "+base+resource+"/{name}",
			"GET "+base+"watch/"+resource, "GET "+base+"watch/"+resource+"/{name}")
	}
	for _, method := range []string{"GET", "PUT", "PATCH"} {
		wantRoutes = append(wantRoutes, method+" /apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name}/status")
	}
	wantRoutes = append(wantRoutes, "POST /apis/authorization.k8s.io/v1/subjectaccessreviews", "POST /apis/authentication.k8s.io/v1/tokenreviews")
	for _, group := range []string{"admissionregistration.k8s.io", "apiextensions.k8s.io", "authorization.k8s.io", "authentication.k8s.io"} {
		wantRoutes = append(wantRoutes, "GET /apis/"+group+"/v1/")
	}
	sort.Strings(wantRoutes)
	if !reflect.DeepEqual(info["routes"], wantRoutes) {
		t.Fatalf("native route inventory differs:\n%v\nwant:\n%v", info["routes"], wantRoutes)
	}
}

const controllerRole = `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"controller"},"rules":[{"apiGroups":["admissionregistration.k8s.io","apiextensions.k8s.io","authorization.k8s.io","authentication.k8s.io"],"resources":["*"],"verbs":["*"]}]}`
const controllerBinding = `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"controller"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"controller"},"subjects":[{"kind":"User","apiGroup":"rbac.authorization.k8s.io","name":"alice"}]}`

func controllerReviewInput(resource, reviewed string) []byte {
	group, body := "authorization.k8s.io", `{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"`+reviewed+`","groups":["body-group"],"resourceAttributes":{"group":"","version":"v1","resource":"secrets","namespace":"body-namespace","name":"body-name","verb":"get"}}}`
	if resource == "tokenreviews" {
		group, body = "authentication.k8s.io", `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"`+reviewed+`"}}`
	}
	rows, _ := json.Marshal([]urlRequest{{ID: "review", Username: "alice", Groups: []string{"caller-group"}, Method: "POST", URL: "/apis/" + group + "/v1/" + resource, Body: body}})
	return rows
}

func TestControllerReviewCallerGateIsSeparateFromBodyResult(t *testing.T) {
	for _, tc := range []struct {
		resource, reviewed string
		result             bool
	}{
		{"subjectaccessreviews", "reviewed-allowed", true}, {"subjectaccessreviews", "reviewed-denied", false},
		{"tokenreviews", "fixture-valid-token", true}, {"tokenreviews", "fixture-invalid-token", false},
	} {
		t.Run(tc.resource+tc.reviewed, func(t *testing.T) {
			rows := controllerReviewInput(tc.resource, tc.reviewed)
			out := evaluateControllerReviews(manifest(controllerRole, controllerBinding), rows)
			if !out.Valid || len(out.Decisions) != 1 {
				t.Fatalf("native review failed: %+v", out)
			}
			row := out.Decisions[0]
			if row.Initial != "Allow" || row.StatusCode != 201 || row.HandlerCalls != 1 || row.Attributes == nil || row.Attributes.Name != "" || row.Attributes.Namespace != "" || row.Attributes.Username != "alice" || row.Attributes.Verb != "create" {
				t.Fatalf("wrong initial gate/handler: %+v", row)
			}
			var response map[string]interface{}
			if err := json.Unmarshal(row.Response, &response); err != nil {
				t.Fatal(err)
			}
			status := response["status"].(map[string]interface{})
			if tc.resource == "subjectaccessreviews" {
				if status["allowed"] != tc.result || (status["denied"] == true) == tc.result || row.ReviewAttributes == nil || row.ReviewAttributes.Username != tc.reviewed || row.ReviewAttributes.Namespace != "body-namespace" || row.ReviewAttributes.Name != "body-name" || row.ReviewAttributes.Verb != "get" {
					t.Fatalf("wrong reviewed subject: %+v %s", row, row.Response)
				}
			} else if (status["authenticated"] == true) != tc.result || row.AuthenticatedToken != tc.reviewed {
				t.Fatalf("wrong token result: %+v %s", row, row.Response)
			}
			denied := evaluateControllerReviews(manifest(controllerRole), rows)
			if !denied.Valid || denied.Decisions[0].Initial != "NoOpinion" || denied.Decisions[0].StatusCode != 403 || denied.Decisions[0].HandlerCalls != 0 || denied.Decisions[0].ReviewAttributes != nil || denied.Decisions[0].AuthenticatedToken != "" {
				t.Fatalf("ungranted caller reached review: %+v", denied)
			}
		})
	}
}

func TestControllerNativeURLAttributes(t *testing.T) {
	local := strings.Replace(strings.Replace(controllerBinding, `"kind":"ClusterRoleBinding"`, `"kind":"RoleBinding"`, 1), `"metadata":{"name":"controller"}`, `"metadata":{"name":"controller","namespace":"demo"}`, 1)
	for resource, group := range controllerBaseGroups {
		base := "/apis/" + group + "/v1/" + resource
		for _, tc := range []struct{ method, path, verb, name string }{
			{"GET", base + "/fixture", "get", "fixture"}, {"HEAD", base + "/fixture", "get", "fixture"},
			{"GET", base, "list", ""}, {"GET", base + "?fieldSelector=metadata.name%3Dfixture", "list", "fixture"},
			{"GET", base + "?watch=true&fieldSelector=metadata.name%3Dfixture", "watch", "fixture"},
			{"POST", base, "create", ""}, {"PUT", base + "/fixture", "update", "fixture"},
			{"PATCH", base + "/fixture", "patch", "fixture"}, {"DELETE", base + "/fixture", "delete", "fixture"},
			{"DELETE", base + "?fieldSelector=metadata.name%3Dfixture", "deletecollection", ""},
		} {
			out := evaluateCoverageURLs(manifest(controllerRole, controllerBinding), coverageURLInput(tc.method, tc.path))
			if !out.Valid || len(out.Decisions) != 1 {
				t.Fatalf("native URL failed: %+v", out)
			}
			row := out.Decisions[0]
			a := row.Attributes
			if row.Decision != "Allow" || a.APIGroup != group || a.Resource != resource || a.Namespace != "" || a.Name != tc.name || a.Verb != tc.verb || a.Subresource != "" {
				t.Fatalf("wrong controller projection: %+v", row)
			}
			localResult := evaluateCoverageURLs(manifest(controllerRole, local), coverageURLInput(tc.method, tc.path))
			if !localResult.Valid || localResult.Decisions[0].Decision != "NoOpinion" {
				t.Fatalf("namespaced binding granted cluster API: %+v", localResult)
			}
		}
	}
}
