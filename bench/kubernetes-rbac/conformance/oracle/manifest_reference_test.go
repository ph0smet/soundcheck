package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestManifestSourceFidelity(t *testing.T) {
	// Literal expectations come from the pinned YAML-to-JSON path, not from
	// the Soundcheck reader. Keep values that commonly drift through float64.
	docs, err := decodeSourceDocuments("yaml", []byte("value: 9007199254740993\nyesValue: yes\nnearBool: yeS\ndate: 2026-11-10T10:11:12Z\nquantity: 100m\nversion: 1.2.3\n---\nvalue: 'on'\n"))
	if err != nil || len(docs) != 2 {
		t.Fatalf("documents: %s %v", docs, err)
	}
	var first map[string]json.RawMessage
	if err := json.Unmarshal(docs[0], &first); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"value": "9007199254740993", "yesValue": "true", "nearBool": `"yeS"`,
		"date": `"2026-11-10T10:11:12Z"`, "quantity": `"100m"`, "version": `"1.2.3"`} {
		if string(first[key]) != want {
			t.Errorf("%s got %s want %s", key, first[key], want)
		}
	}
	for _, input := range []string{"value: 1\nvalue: 2\n", "value: good\n---\nbroken: ["} {
		if _, err := decodeSourceDocuments("yaml", []byte(input)); err == nil {
			t.Fatalf("accepted malformed stream %q", input)
		}
	}
	// go-yaml v2's binary fallback accepts a sign after the base prefix.
	// Soundcheck must reject these instead of preserving them as strings.
	for _, input := range []string{"0b-1", "0b+1", "0b_+_1"} {
		docs, err := decodeSourceDocuments("yaml", []byte("value: "+input+"\n"))
		if err != nil || len(docs) != 1 {
			t.Fatal(err)
		}
		var values map[string]json.RawMessage
		if err := json.Unmarshal(docs[0], &values); err != nil {
			t.Fatal(err)
		}
		want := "1"
		if input == "0b-1" {
			want = "-1"
		}
		if string(values["value"]) != want {
			t.Fatalf("binary fallback %s: %s", input, docs[0])
		}
	}
}

func TestManifestTypedListAndNamespace(t *testing.T) {
	input := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: RoleList
items:
  - metadata: {name: reader, generation: 9007199254740993}
    rules: [{apiGroups: [""], resources: [configmaps], verbs: [get]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBindingList
items:
  - metadata: {name: reader}
    roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: reader}
    subjects: [{kind: ServiceAccount, name: app}]
`)
	out, err := referenceManifests("yaml", "team-a", input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Snapshot, []byte(`"generation":9007199254740993`)) {
		t.Fatalf("integer was rounded: %s", out.Snapshot)
	}
	objects, failures := decodeManifest(out.Snapshot)
	if len(failures) != 0 || len(objects.roles) != 1 || len(objects.roleBindings) != 1 {
		t.Fatalf("inventory %v %v", objects, failures)
	}
	if objects.roles[0].Namespace != "team-a" || objects.roleBindings[0].Namespace != "team-a" || objects.roleBindings[0].Subjects[0].Namespace != "" {
		t.Fatal("namespace default changed subject or missed object")
	}
	// Upstream inference does not repair a singly missing GVK field.
	partial := bytes.Replace(input, []byte("  - metadata: {name: reader, generation:"), []byte("  - kind: Role\n    metadata: {name: reader, generation:"), 1)
	if _, err := referenceManifests("yaml", "team-a", partial); err == nil {
		t.Fatal("partially missing type metadata accepted")
	}
}

func TestItemsWithoutListSuffixIsUpstreamList(t *testing.T) {
	// Kubernetes detects list-ness by the items member, not the kind suffix.
	// Soundcheck must reject such wrappers instead of excluding their grants.
	input := []byte(`{"apiVersion":"example.com/v1","kind":"Bundle","items":[
	  {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role",
	   "metadata":{"name":"reader","namespace":"team-a"},"rules":[]}]}`)
	out, err := referenceManifests("json", "", input)
	if err != nil {
		t.Fatal(err)
	}
	objects, failures := decodeManifest(out.Snapshot)
	if len(failures) != 0 || len(objects.roles) != 1 {
		t.Fatalf("items wrapper did not retain RBAC: %s %v", out.Snapshot, failures)
	}
}
