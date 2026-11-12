package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func applyTestRequest(resource, group, op string) applyRequest {
	ns := "demo"
	if resource == "nodes" {
		ns = ""
	}
	return applyRequest{ID: "test", Username: "alice", Groups: []string{}, Operation: op, APIGroup: group,
		Resource: resource, Namespace: ns, Name: "example", ResourceRequest: true}
}

func applyPolicy(verbs []string, names []string) []byte {
	rule := map[string]interface{}{"verbs": verbs, "apiGroups": []string{"*"}, "resources": []string{"*"}}
	if names != nil {
		rule["resourceNames"] = names
	}
	policy := map[string]interface{}{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": map[string]string{"name": "allowed"}, "rules": []interface{}{rule}}
	encoded, _ := json.Marshal(policy)
	return manifest(string(encoded), `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"allowed"},"roleRef":{"kind":"ClusterRole","name":"allowed","apiGroup":"rbac.authorization.k8s.io"},"subjects":[{"kind":"User","name":"alice","apiGroup":"rbac.authorization.k8s.io"}]}`)
}

func TestNativeApplyAllBaseResources(t *testing.T) {
	for _, target := range [][2]string{{"configmaps", ""}, {"secrets", ""}, {"pods", ""}, {"services", ""}, {"endpoints", ""}, {"nodes", ""}, {"deployments", "apps"}, {"endpointslices", "discovery.k8s.io"}} {
		for _, op := range []string{"apply-existing", "apply-missing"} {
			for _, grants := range []struct {
				verbs   []string
				names   []string
				allowed bool
				stages  int
			}{
				{[]string{"patch", "create"}, nil, true, 2},
				{[]string{"patch"}, nil, op == "apply-existing", 2},
				{[]string{"create"}, nil, false, 1},
				{[]string{"patch", "create"}, []string{"example"}, true, 2},
				{[]string{"patch", "create"}, []string{"other"}, false, 1},
			} {
				t.Run(target[0]+"/"+op+"/"+fmt.Sprint(grants.verbs)+fmt.Sprint(grants.names), func(t *testing.T) {
					r := applyTestRequest(target[0], target[1], op)
					data, _ := json.Marshal([]applyRequest{r})
					out := evaluateApply(applyPolicy(grants.verbs, grants.names), data)
					if !out.Valid || len(out.Decisions) != 1 {
						t.Fatalf("native handler: %+v", out)
					}
					got := out.Decisions[0]
					if (got.Decision == "Allow") != grants.allowed {
						t.Fatalf("decision mismatch: %+v", got)
					}
					stages := grants.stages
					if op == "apply-existing" {
						stages = 1
					}
					if len(got.Stages) != stages {
						t.Fatalf("wrong stages: %+v", got)
					}
					for i, stage := range got.Stages {
						verb := "patch"
						if i == 1 {
							verb = "create"
						}
						a := stage.Attributes
						if a.Verb != verb || a.Name != r.Name || a.Namespace != r.Namespace || a.APIGroup != r.APIGroup || a.APIVersion != "v1" || a.Resource != r.Resource || a.Subresource != "" || !a.ResourceRequest || a.Username != r.Username || a.Groups == nil || a.Path == "" {
							t.Fatalf("incorrect native attributes: %+v", a)
						}
					}
					entered := got.Stages[0].Decision == "Allow"
					if got.HandlerEntered != entered || (got.StorageReads == 1) != entered {
						t.Fatalf("wrong native entry/storage: %+v", got)
					}
					wantStatus := 403
					if grants.allowed {
						wantStatus = 200
						if op == "apply-missing" {
							wantStatus = 201
						}
					}
					if got.HTTPStatus != wantStatus {
						t.Fatalf("wrong HTTP result: %+v", got)
					}
				})
			}
		}
	}
}

func TestNativeApplyRequiresNoGetOrUpdate(t *testing.T) {
	r := applyTestRequest("configmaps", "", "apply-missing")
	auth := authorizer.AuthorizerFunc(func(_ context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
		if attrs.GetVerb() != "patch" && attrs.GetVerb() != "create" {
			t.Errorf("unexpected authorization: %s", attrs.GetVerb())
			return authorizer.DecisionNoOpinion, "", nil
		}
		return authorizer.DecisionAllow, "", nil
	})
	out, err := runNativeApply(r, auth, nil)
	if err != nil || out.Decision != "Allow" || len(out.Stages) != 2 {
		t.Fatalf("native request: %+v %v", out, err)
	}
}

func TestNativeApplyErrorsDoNotBecomeDenials(t *testing.T) {
	r := applyTestRequest("configmaps", "", "apply-missing")
	for _, target := range []string{"patch", "create"} {
		for _, allow := range []bool{false, true} {
			auth := authorizer.AuthorizerFunc(func(_ context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
				if a.GetVerb() == target {
					if allow {
						return authorizer.DecisionAllow, "still allowed", fmt.Errorf("evaluation error")
					}
					return authorizer.DecisionNoOpinion, "", fmt.Errorf("evaluation error")
				}
				return authorizer.DecisionAllow, "", nil
			})
			out, err := runNativeApply(r, auth, nil)
			if allow && (err != nil || out.Decision != "Allow") {
				t.Fatalf("Allow must precede error: %+v %v", out, err)
			}
			if !allow && (err == nil || out.HTTPStatus != 500) {
				t.Fatalf("authorizer error must remain visible: %+v %v", out, err)
			}
		}
	}
}

func TestNativeApplyMalformedOrMismatchedBodyStopsBeforeCreateAuthorization(t *testing.T) {
	r := applyTestRequest("configmaps", "", "apply-missing")
	auth := authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
		return authorizer.DecisionAllow, "", nil
	})
	for _, body := range []string{`{broken`, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"other","namespace":"demo"}}`, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"example","namespace":"other"}}`, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"example","namespace":"demo","uid":"not-stored"}}`} {
		out, err := runNativeApply(r, auth, &body)
		if err == nil || len(out.Stages) != 1 || out.Stages[0].Attributes.Verb != "patch" || out.Stages[0].Attributes.Name != "example" {
			t.Fatalf("invalid body should stop before named-create: %+v %v", out, err)
		}
	}
}

func TestNativeApplyServiceBodyNameBoundaryIsNotNoOpinion(t *testing.T) {
	r := applyTestRequest("services", "", "apply-missing")
	r.Name = "a.b" // DNS1123 subdomain, but not a valid Service body name.
	if err := applyRequestDomain(r); err != nil {
		t.Fatalf("the authorization tuple is in-domain: %v", err)
	}
	auth := authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
		return authorizer.DecisionAllow, "allowed", nil
	})
	observed, err := runNativeApply(r, auth, nil)
	if err == nil || observed.HTTPStatus != 422 || len(observed.Stages) != 1 ||
		observed.Stages[0].Attributes.Verb != "patch" || observed.Stages[0].Attributes.Name != "a.b" ||
		observed.Stages[0].Decision != "Allow" {
		t.Fatalf("body validation must remain separate from authorization: %+v %v", observed, err)
	}
	data, _ := json.Marshal([]applyRequest{r})
	out := evaluateApply(applyPolicy([]string{"patch", "create"}, nil), data)
	if out.Valid || len(out.Decisions) != 0 || len(out.ValidationErrors) == 0 {
		t.Fatalf("a body-validation failure must not become an accepted NoOpinion decision: %+v", out)
	}
}

func TestApplyStrictInput(t *testing.T) {
	r := applyTestRequest("pods", "", "apply-missing")
	data, _ := json.Marshal([]applyRequest{r})
	for _, changed := range []string{
		strings.Replace(string(data), `"operation":"apply-missing"`, `"verb":"patch"`, 1),
		strings.Replace(string(data), `"operation":"apply-missing"`, `"operation":"apply-missing","operation":"patch"`, 1),
		strings.Replace(string(data), `"subresource":""`, `"subresource":"status"`, 1),
		strings.Replace(string(data), `"name":"example"`, `"name":""`, 1),
		strings.Replace(string(data), `"groups":[]`, `"groups":[null]`, 1),
		strings.Replace(string(data), `"resourceRequest":true`, `"resourceRequest":null`, 1),
		strings.Replace(string(data), `"apiGroup":""`, `"apiGroup":"apps"`, 1),
		strings.Replace(string(data), `"namespace":"demo"`, `"namespace":""`, 1),
		string(data[:len(data)-1]) + "," + string(data[1:]),
	} {
		out := evaluateApply(applyPolicy([]string{"*"}, nil), []byte(changed))
		if out.Valid || len(out.Decisions) != 0 || len(out.ValidationErrors) == 0 {
			t.Fatalf("accepted invalid input: %s: %+v", changed, out)
		}
	}
}
