package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInitialCollectionAuthorizationIgnoresBodyNames(t *testing.T) {
	policy := strings.Replace(readRole, `["get","list","watch"]`, `["create","deletecollection"]`, 1)
	for _, names := range []struct{ value, expected string }{
		{`[]`, "Allow"}, {`[""]`, "Allow"}, {`["token"]`, "NoOpinion"}, {`["*"]`, "NoOpinion"},
	} {
		for _, body := range []string{"", `{"metadata":{"name":"token"}}`, `{"metadata":{"name":"other"}}`, `{"metadata":{"generateName":"token-"}}`, `{broken`} {
			for _, method := range []string{"POST", "DELETE"} {
				for _, query := range []string{"", "?fieldSelector=metadata.name%3Dtoken"} {
					req := urlRequest{ID: "request", Username: "alice", Groups: []string{}, Method: method,
						URL: "/api/v1/namespaces/demo/secrets" + query, Body: body}
					data, err := json.Marshal([]urlRequest{req})
					if err != nil {
						t.Fatal(err)
					}
					out := evaluateURLs(manifest(strings.Replace(policy, `["token"]`, names.value, 1), binding), data)
					verb := "create"
					if method == "DELETE" {
						verb = "deletecollection"
					}
					if !out.Valid || len(out.Decisions) != 1 {
						t.Fatalf("invalid native result: %+v", out)
					}
					got := out.Decisions[0]
					if got.Attributes.Name != "" || got.Attributes.Verb != verb || got.Attributes.Namespace != "demo" ||
						got.Decision != names.expected || got.Error != "" || got.FieldSelectorError || got.LabelSelectorError {
						t.Fatalf("names=%s method=%s body=%q query=%s: %+v", names.value, method, body, query, got)
					}
				}
			}
		}
	}
}

func TestOptionalURLBodyIsStrict(t *testing.T) {
	valid := strings.TrimSuffix(string(urlInput("/api/v1/namespaces/demo/secrets")), "}]")
	for _, suffix := range []string{`,"body":null}]`, `,"body":{}}]`, `,"body":123}]`, `,"body":"x","body":"y"}]`} {
		out := evaluateURLs(manifest(readRole, binding), []byte(valid+suffix))
		if out.Valid || len(out.ValidationErrors) == 0 || len(out.Decisions) != 0 {
			t.Fatalf("invalid optional body accepted: %s: %+v", suffix, out)
		}
	}
	for _, suffix := range []string{"}]", `,"body":""}]`, `,"body":"not object JSON"}]`} {
		out := evaluateURLs(manifest(readRole, binding), []byte(valid+suffix))
		if !out.Valid || len(out.Decisions) != 1 {
			t.Fatalf("raw/missing body rejected: %+v", out)
		}
	}
}
