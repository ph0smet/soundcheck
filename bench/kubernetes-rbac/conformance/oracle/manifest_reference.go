package main

// Independent ingestion oracle: Kubernetes' YAML conversion and unstructured
// decoder operate on the ORIGINAL source, before Soundcheck preparation. This
// is a test adapter, not a second implementation of Soundcheck's strict subset.
import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	strictjson "sigs.k8s.io/json"
	"sigs.k8s.io/yaml"
)

type manifestReference struct {
	SchemaVersion int               `json:"schema_version"`
	Kind          string            `json:"kind"`
	SourceSHA256  string            `json:"source_sha256"`
	Documents     []json.RawMessage `json:"documents"`
	Snapshot      json.RawMessage   `json:"snapshot"`
}

func decodeSourceDocuments(format string, data []byte) ([]json.RawMessage, error) {
	documents := []json.RawMessage{}
	if format == "json" {
		var value interface{}
		strictErrors, err := strictjson.UnmarshalStrict(data, &value)
		if err != nil || len(strictErrors) != 0 {
			return nil, fmt.Errorf("invalid strict JSON: %v %v", err, strictErrors)
		}
		return append(documents, json.RawMessage(data)), nil
	}
	if format != "yaml" {
		return nil, fmt.Errorf("expected json or yaml")
	}
	reader := k8syaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	for {
		document, err := reader.Read()
		if err == io.EOF {
			return documents, nil
		}
		if err != nil {
			return nil, err
		}
		converted, err := yaml.YAMLToJSONStrict(document)
		if err != nil {
			return nil, err
		}
		documents = append(documents, json.RawMessage(converted))
	}
}

func referenceManifests(format, namespace string, data []byte) (manifestReference, error) {
	out := manifestReference{SchemaVersion: 1, Kind: "upstream_manifest_reference", SourceSHA256: sha256Text(data)}
	if namespace != "" && len(validation.IsDNS1123Label(namespace)) != 0 {
		return out, fmt.Errorf("invalid namespace context")
	}
	documents, err := decodeSourceDocuments(format, data)
	if err != nil {
		return out, err
	}
	out.Documents = documents
	items := []json.RawMessage{}
	var collect func([]byte) error
	collect = func(raw []byte) error {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil // Empty documents; explicit null is rejected by Soundcheck.
		}
		object, _, err := unstructured.UnstructuredJSONScheme.Decode(raw, nil, nil)
		if err != nil {
			return err
		}
		switch object := object.(type) {
		case *unstructured.UnstructuredList:
			// The pinned upstream implementation supplies typed item GVKs only
			// when both are empty. Do not reproduce that rule in this adapter.
			for _, child := range object.Items {
				encoded, err := json.Marshal(child.Object)
				if err != nil {
					return err
				}
				if err := collect(encoded); err != nil {
					return err
				}
			}
		case *unstructured.Unstructured:
			if object.GroupVersionKind().Group != "rbac.authorization.k8s.io" {
				switch object.GetKind() {
				case "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding":
					return fmt.Errorf("RBAC kind has missing or conflicting API group")
				}
				return nil // Deliberate resource-domain projection for this oracle.
			}
			// Namespace is explicit client context, not RBAC scheme defaulting.
			// Apply it only where an empty namespaced object's request context
			// supplies it; never override a declared namespace or any subject.
			if (object.GetKind() == "Role" || object.GetKind() == "RoleBinding") && object.GetNamespace() == "" && namespace != "" {
				object.SetNamespace(namespace)
			}
			encoded, err := json.Marshal(object.Object)
			if err != nil {
				return err
			}
			items = append(items, json.RawMessage(encoded))
		default:
			return fmt.Errorf("unexpected upstream unstructured type")
		}
		return nil
	}
	for _, document := range documents {
		if err := collect(document); err != nil {
			return out, err
		}
	}
	out.Snapshot, err = json.Marshal(map[string]interface{}{"apiVersion": "v1", "kind": "List", "items": items})
	if err != nil {
		return out, err
	}
	if _, failures := decodeManifest(out.Snapshot); len(failures) != 0 {
		return out, fmt.Errorf("upstream RBAC validation: %v", failures)
	}
	return out, nil
}

func manifestReferenceFiles(args []string) {
	if len(args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: rbac-oracle --manifest-reference json|yaml DEFAULT_NAMESPACE_OR_EMPTY SOURCE")
		os.Exit(2)
	}
	data, err := os.ReadFile(args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	out, err := referenceManifests(args[0], args[1], data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
