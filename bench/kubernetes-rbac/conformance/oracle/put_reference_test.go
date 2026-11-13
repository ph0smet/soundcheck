package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestNativePutServicesAndEndpoints(t *testing.T) {
	for _, resource := range []string{"services", "endpoints"} {
		for _, op := range []string{"update-existing", "update-missing"} {
			for _, tc := range []struct {
				verbs, names []string
				allowed      bool
				stages       int
			}{
				{[]string{"get"}, nil, false, 1},
				{[]string{"create"}, nil, false, 1},
				{[]string{"update"}, nil, op == "update-existing", 2},
				{[]string{"update", "create"}, nil, true, 2},
				{[]string{"update", "create"}, []string{"example"}, true, 2},
				{[]string{"update", "create"}, []string{"other"}, false, 1},
				{[]string{"update", "create"}, []string{""}, false, 1},
			} {
				t.Run(resource+"/"+op+fmt.Sprint(tc.verbs, tc.names), func(t *testing.T) {
					r := applyTestRequest(resource, "", op)
					input, _ := json.Marshal([]applyRequest{r})
					out := evaluatePut(applyPolicy(tc.verbs, tc.names), input)
					if !out.Valid || len(out.Decisions) != 1 {
						t.Fatalf("native PUT: %+v", out)
					}
					row := out.Decisions[0]
					stages := tc.stages
					if op == "update-existing" {
						stages = 1
					}
					if (row.Decision == "Allow") != tc.allowed || len(row.Stages) != stages {
						t.Fatalf("grant/branch mismatch: %+v", row)
					}
					wantStatus := 403
					if tc.allowed {
						wantStatus = 200
						if op == "update-missing" {
							wantStatus = 201
						}
					}
					if row.HTTPStatus != wantStatus {
						t.Fatalf("status: %+v", row)
					}
					for i, stage := range row.Stages {
						verb := "update"
						if i == 1 {
							verb = "create"
						}
						a := stage.Attributes
						if a.Verb != verb || a.Name != r.Name || a.Namespace != r.Namespace || a.Resource != resource || a.APIGroup != "" || a.APIVersion != "v1" || a.Subresource != "" || !a.ResourceRequest || a.Username != r.Username || a.Groups == nil || a.Path != "/api/v1/namespaces/demo/"+resource+"/example" {
							t.Fatalf("wrong native tuple: %+v", a)
						}
					}
					entered := row.Stages[0].Decision == "Allow"
					if row.HandlerEntered != entered || (row.StorageReads == 1) != entered {
						t.Fatalf("initial denial must stop handler/storage: %+v", row)
					}
				})
			}
		}
	}
}

func TestNativePutOtherBaseStrategiesDoNotCreate(t *testing.T) {
	for _, target := range [][2]string{{"configmaps", ""}, {"secrets", ""}, {"pods", ""}, {"nodes", ""}, {"deployments", "apps"}, {"endpointslices", "discovery.k8s.io"}} {
		r := applyTestRequest(target[0], target[1], "update-missing")
		auth := authorizer.AuthorizerFunc(func(_ context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
			if a.GetVerb() != "update" {
				t.Errorf("unexpected extra authorization for %s: %s", target[0], a.GetVerb())
			}
			return authorizer.DecisionAllow, "", nil
		})
		out, err := runNativePut(r, auth, nil)
		if err == nil || out.HTTPStatus != 404 || len(out.Stages) != 1 || !out.HandlerEntered || out.StorageReads != 1 {
			t.Fatalf("missing unsupported create-on-update must stay NotFound: %+v %v", out, err)
		}
		if err := putRequestDomain(r); err == nil {
			t.Fatalf("unsupported resource accepted in public PUT domain: %+v", r)
		}
	}
}

func TestNativePutNamedCreateFromSeparateBinding(t *testing.T) {
	// The extra named create grant is supplied by a different Role/Binding.
	var list map[string]interface{}
	if err := json.Unmarshal(applyPolicy([]string{"update"}, nil), &list); err != nil {
		t.Fatal(err)
	}
	var second map[string]interface{}
	if err := json.Unmarshal(applyPolicy([]string{"create"}, []string{"example"}), &second); err != nil {
		t.Fatal(err)
	}
	for _, item := range second["items"].([]interface{}) {
		obj := item.(map[string]interface{})
		obj["metadata"].(map[string]interface{})["name"] = "creator"
		if ref, ok := obj["roleRef"].(map[string]interface{}); ok {
			ref["name"] = "creator"
		}
		list["items"] = append(list["items"].([]interface{}), obj)
	}
	policy, _ := json.Marshal(list)
	r := applyTestRequest("endpoints", "", "update-missing")
	input, _ := json.Marshal([]applyRequest{r})
	out := evaluatePut(policy, input)
	if !out.Valid || len(out.Decisions) != 1 || out.Decisions[0].Decision != "Allow" || len(out.Decisions[0].Stages) != 2 {
		t.Fatalf("split grants: %+v", out)
	}
	if !strings.Contains(out.Decisions[0].Stages[0].Reason, "allowed") || !strings.Contains(out.Decisions[0].Stages[1].Reason, "creator") {
		t.Fatalf("native sources lost: %+v", out)
	}
}

func TestNativePutBodyAndAuthorizerErrorsStayVisible(t *testing.T) {
	r := applyTestRequest("endpoints", "", "update-missing")
	allow := authorizer.AuthorizerFunc(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
		return authorizer.DecisionAllow, "", nil
	})
	for _, body := range []string{`{broken`, `{"apiVersion":"v1","kind":"Endpoints","metadata":{"name":"other","namespace":"demo"}}`, `{"apiVersion":"v1","kind":"Endpoints","metadata":{"name":"example","namespace":"other"}}`} {
		row, err := runNativePut(r, allow, &body)
		if err == nil || len(row.Stages) != 1 || row.Stages[0].Attributes.Verb != "update" {
			t.Fatalf("invalid body must not become NoOpinion: %+v %v", row, err)
		}
	}
	for _, verb := range []string{"update", "create"} {
		for _, granted := range []bool{false, true} {
			auth := authorizer.AuthorizerFunc(func(_ context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
				if a.GetVerb() != verb {
					return authorizer.DecisionAllow, "", nil
				}
				d := authorizer.DecisionNoOpinion
				if granted {
					d = authorizer.DecisionAllow
				}
				return d, "", fmt.Errorf("reference evaluation error")
			})
			row, err := runNativePut(r, auth, nil)
			if granted && (err != nil || row.Decision != "Allow") {
				t.Fatalf("Allow before error: %+v %v", row, err)
			}
			if !granted && (err == nil || row.HTTPStatus != 500) {
				t.Fatalf("error hidden: %+v %v", row, err)
			}
		}
	}
	r.Resource, r.Name = "services", "a.b"
	if err := putRequestDomain(r); err != nil {
		t.Fatal("authorization-name domain unexpectedly narrowed", err)
	}
	row, err := runNativePut(r, allow, nil)
	if err == nil || row.HTTPStatus != 422 || len(row.Stages) != 1 {
		t.Fatalf("Service body-name boundary hidden: %+v %v", row, err)
	}
}

func TestNativePutStrictRequests(t *testing.T) {
	r := applyTestRequest("services", "", "update-missing")
	encoded, _ := json.Marshal([]applyRequest{r})
	valid := string(encoded)
	for _, bad := range []string{`null`, `[]`, `{}`, valid + `{}`, strings.Replace(valid, `"groups":[]`, `"groups":null`, 1), strings.Replace(valid, `"operation":"update-missing"`, `"operation":"apply-missing"`, 1), strings.Replace(valid, `"resource":"services"`, `"resource":"pods"`, 1), strings.Replace(valid, `"subresource":""`, `"subresource":"status"`, 1), strings.Replace(valid, `"name":"example"`, `"name":""`, 1), strings.Replace(valid, `"namespace":"demo"`, `"namespace":""`, 1), strings.Replace(valid, `"id":"test"`, `"extra":true,"id":"test"`, 1), strings.Replace(valid, `"id":"test"`, `"id":"test","id":"test"`, 1)} {
		out := evaluatePut(applyPolicy([]string{"*"}, nil), []byte(bad))
		if out.Valid || len(out.ValidationErrors) == 0 || len(out.Decisions) != 0 {
			t.Fatalf("invalid PUT reference input accepted: %s %+v", bad, out)
		}
	}
}
