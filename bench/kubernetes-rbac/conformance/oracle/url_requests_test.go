package main

import (
	"encoding/json"
	"strings"
	"testing"
)

const readRole = `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"reader","namespace":"demo"},"rules":[{"verbs":["get","list","watch"],"apiGroups":[""],"resources":["secrets"],"resourceNames":["token"]}]}`

func urlInput(target string) []byte {
	data, err := json.Marshal([]urlRequest{{ID: "request", Username: "alice", Groups: []string{}, Method: "GET", URL: target}})
	if err != nil {
		panic(err)
	}
	return data
}

func TestProductionRequestInfoAndAuthorizerAttributes(t *testing.T) {
	for _, tc := range []struct {
		name, target, verb, namespace, objectName, decision string
		fieldError                                          bool
	}{
		{"named get", "/api/v1/namespaces/demo/secrets/token", "get", "demo", "token", "Allow", false},
		{"named get watch query is still get", "/api/v1/namespaces/demo/secrets/token?watch=true", "get", "demo", "token", "Allow", false},
		{"list without selector", "/api/v1/namespaces/demo/secrets", "list", "demo", "", "NoOpinion", false},
		{"exact list", "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.name%3Dtoken", "list", "demo", "token", "Allow", false},
		{"double equals", "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.name%3D%3Dtoken", "list", "demo", "token", "Allow", false},
		{"wrong exact name", "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.name%3Dother", "list", "demo", "other", "NoOpinion", false},
		{"not equal is not exact", "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.name%21%3Dtoken", "list", "demo", "", "NoOpinion", false},
		{"empty equality", "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.name%3D", "list", "demo", "", "NoOpinion", false},
		{"other field", "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.namespace%3Ddemo", "list", "demo", "", "NoOpinion", false},
		{"malformed selector", "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.name%3Dtoken%2Cbroken", "list", "demo", "", "NoOpinion", true},
		{"malformed numeric clears name", "/api/v1/namespaces/demo/secrets?limit=broken&fieldSelector=metadata.name%3Dtoken", "list", "demo", "", "NoOpinion", false},
		{"malformed numeric keeps watch", "/api/v1/namespaces/demo/secrets?watch=true&timeoutSeconds=broken&fieldSelector=metadata.name%3Dtoken", "watch", "demo", "", "NoOpinion", false},
		{"repeated selector takes first", "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.name%3Dtoken&fieldSelector=metadata.name%3Dother", "list", "demo", "token", "Allow", false},
		{"watch without selector", "/api/v1/namespaces/demo/secrets?watch=true", "watch", "demo", "", "NoOpinion", false},
		{"watch selected", "/api/v1/namespaces/demo/secrets?watch=true&fieldSelector=metadata.name%3Dtoken", "watch", "demo", "token", "Allow", false},
		{"watch one", "/api/v1/namespaces/demo/secrets?watch=1&fieldSelector=metadata.name%3Dtoken", "watch", "demo", "token", "Allow", false},
		{"watch garbage", "/api/v1/namespaces/demo/secrets?watch=garbage&fieldSelector=metadata.name%3Dtoken", "watch", "demo", "token", "Allow", false},
		{"watch empty", "/api/v1/namespaces/demo/secrets?watch=&fieldSelector=metadata.name%3Dtoken", "watch", "demo", "token", "Allow", false},
		{"watch f", "/api/v1/namespaces/demo/secrets?watch=f&fieldSelector=metadata.name%3Dtoken", "watch", "demo", "token", "Allow", false},
		{"watch false", "/api/v1/namespaces/demo/secrets?watch=false&fieldSelector=metadata.name%3Dtoken", "list", "demo", "token", "Allow", false},
		{"watch zero", "/api/v1/namespaces/demo/secrets?watch=0&fieldSelector=metadata.name%3Dtoken", "list", "demo", "token", "Allow", false},
		{"legacy collection ignores selector", "/api/v1/watch/namespaces/demo/secrets?fieldSelector=metadata.name%3Dtoken", "watch", "demo", "", "NoOpinion", false},
		{"legacy named watch", "/api/v1/watch/namespaces/demo/secrets/token?fieldSelector=metadata.name%3Dother", "watch", "demo", "token", "Allow", false},
		{"all namespaces", "/api/v1/secrets", "list", "", "", "NoOpinion", false},
		{"namespace field does not narrow authorization", "/api/v1/secrets?fieldSelector=metadata.namespace%3Ddemo%2Cmetadata.name%3Dtoken", "list", "", "token", "NoOpinion", false},
		{"name invalid as path segment", "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.name%3Da%2Fb", "list", "demo", "", "NoOpinion", false},
		{"star is literal attribute outside model domain", "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.name%3D%2A", "list", "demo", "*", "NoOpinion", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := evaluateURLs(manifest(readRole, binding), urlInput(tc.target))
			if !out.Valid || len(out.Decisions) != 1 {
				t.Fatalf("upstream extraction failed: %+v", out)
			}
			row := out.Decisions[0]
			a := row.Attributes
			if a.Verb != tc.verb || a.Namespace != tc.namespace || a.Name != tc.objectName ||
				a.Resource != "secrets" || a.APIGroup != "" || a.APIVersion != "v1" ||
				a.Subresource != "" || !a.ResourceRequest || a.Username != "alice" || len(a.Groups) != 0 ||
				row.Decision != tc.decision || row.FieldSelectorError != tc.fieldError || row.LabelSelectorError || row.Error != "" {
				t.Fatalf("unexpected actual request attributes/authorization: %+v", row)
			}
		})
	}
}

func TestCollectionNamesAndBindingScope(t *testing.T) {
	for _, tc := range []struct {
		name, names, target, want string
	}{
		{"empty name matches unnamed list", `[""]`, "/api/v1/namespaces/demo/secrets", "Allow"},
		{"empty name matches unnamed watch", `[""]`, "/api/v1/namespaces/demo/secrets?watch=true", "Allow"},
		{"empty name does not match selected list", `[""]`, "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.name%3Dtoken", "NoOpinion"},
		{"literal star does not match unnamed list", `["*"]`, "/api/v1/namespaces/demo/secrets", "NoOpinion"},
		{"literal star does not match ordinary selected name", `["*"]`, "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.name%3Dtoken", "NoOpinion"},
		{"literal star matches literal upstream name", `["*"]`, "/api/v1/namespaces/demo/secrets?fieldSelector=metadata.name%3D%2A", "Allow"},
		{"empty array is unrestricted", `[]`, "/api/v1/namespaces/demo/secrets", "Allow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := strings.Replace(readRole, `["token"]`, tc.names, 1)
			out := evaluateURLs(manifest(policy, binding), urlInput(tc.target))
			if !out.Valid || len(out.Decisions) != 1 || out.Decisions[0].Decision != tc.want {
				t.Fatalf("literal resourceNames behavior changed: %+v", out)
			}
		})
	}
	clusterRole := strings.Replace(strings.Replace(readRole, `"kind":"Role"`, `"kind":"ClusterRole"`, 1), `,"namespace":"demo"`, "", 1)
	localClusterBinding := strings.Replace(binding, `"kind":"Role","name":"reader"`, `"kind":"ClusterRole","name":"reader"`, 1)
	clusterBinding := strings.Replace(strings.Replace(localClusterBinding, `"kind":"RoleBinding"`, `"kind":"ClusterRoleBinding"`, 1), `,"namespace":"demo"`, "", 1)
	for _, tc := range []struct{ name, grant, want string }{
		{"role binding stays local", localClusterBinding, "NoOpinion"},
		{"cluster role binding grants all namespaces", clusterBinding, "Allow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := evaluateURLs(manifest(clusterRole, tc.grant), urlInput("/api/v1/secrets?watch=true&fieldSelector=metadata.name%3Dtoken"))
			if !out.Valid || len(out.Decisions) != 1 || out.Decisions[0].Decision != tc.want || out.Decisions[0].Attributes.Namespace != "" {
				t.Fatalf("all-namespace request unexpectedly reused a namespaced binding: %+v", out)
			}
		})
	}
}

func TestURLModeStrictInput(t *testing.T) {
	valid := string(urlInput("/api/v1/namespaces/demo/secrets/token"))
	for _, bad := range []string{
		`null`, `[]`, `{}`, valid + `{}`, strings.Replace(valid, `"GET"`, `null`, 1),
		strings.Replace(valid, `"groups":[]`, `"groups":[null]`, 1),
		strings.Replace(valid, `"groups":[]`, `"groups":["x","x"]`, 1),
		strings.Replace(valid, `"method":"GET"`, `"method":"GET","method":"POST"`, 1),
		strings.Replace(valid, `"method":"GET"`, `"extra":true,"method":"GET"`, 1),
		strings.Replace(valid, `"method":"GET",`, "", 1),
		strings.Replace(valid, `"GET"`, `"get"`, 1),
		strings.Replace(valid, `/api/v1/namespaces/demo/secrets/token`, `https://example.test/api/v1/secrets`, 1),
		strings.Replace(valid, `/api/v1/namespaces/demo/secrets/token`, `//example.test/api/v1/secrets`, 1),
		strings.Replace(valid, `/api/v1/namespaces/demo/secrets/token`, `/api/v1/secrets#ignored`, 1),
		strings.TrimSuffix(valid, "]") + "," + strings.TrimPrefix(valid, "["),
	} {
		out := evaluateURLs(manifest(readRole, binding), []byte(bad))
		if out.Valid || len(out.ValidationErrors) == 0 || len(out.Decisions) != 0 {
			t.Fatalf("invalid adapter input authorized: %s: %+v", bad, out)
		}
	}
	invalidManifest := strings.Replace(readRole, `"verbs":["get","list","watch"]`, `"verbs":[]`, 1)
	if out := evaluateURLs(manifest(invalidManifest, binding), []byte(valid)); out.Valid || len(out.Decisions) != 0 {
		t.Fatalf("invalid original object authorized: %+v", out)
	}
}
