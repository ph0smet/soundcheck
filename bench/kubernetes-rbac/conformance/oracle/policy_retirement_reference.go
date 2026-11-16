package main

// Ordinary policy deletion reaches Kubernetes' unchanged generic Store.Delete
// through the real policybased wrapper. Only the final storage interface is a
// fixture: it retains the old object, checks validation/preconditions, and removes
// it. No finalizers, garbage collector, admission or concurrent store is simulated.
import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/endpoints/handlers"
	registry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage"
)

func policyRetirementInventoryBoundary(data []byte) error {
	var list struct {
		Items []struct {
			Metadata map[string]json.RawMessage `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	for index, item := range list.Items {
		for key := range item.Metadata {
			switch key {
			case "name", "namespace", "labels", "annotations":
			default:
				return fmt.Errorf("state item %d metadata.%s is outside the strict retirement snapshot", index, key)
			}
		}
	}
	_, err := policySequenceInventory(data)
	return err
}

type policyRetirementStorage struct {
	storage.Interface
	object kruntime.Object
	result *policyChangeResult
}

func (s *policyRetirementStorage) Get(ctx context.Context, key string, opts storage.GetOptions, out kruntime.Object) error {
	if s.object == nil {
		return storage.NewKeyNotFoundError(key, 0)
	}
	reflect.ValueOf(out).Elem().Set(reflect.ValueOf(s.object.DeepCopyObject()).Elem())
	return nil
}

func (s *policyRetirementStorage) Delete(ctx context.Context, key string, out kruntime.Object, preconditions *storage.Preconditions,
	validation storage.ValidateObjectFunc, cached kruntime.Object, options storage.DeleteOptions) error {
	if err := s.Get(ctx, key, storage.GetOptions{}, out); err != nil {
		return err
	}
	if err := preconditions.Check(key, s.object); err != nil {
		return err
	}
	if validation != nil {
		if err := validation(ctx, s.object); err != nil {
			return err
		}
	}
	s.result.StorageCalls++
	s.object = nil
	return nil
}

func (s *policyChangeStore) Delete(ctx context.Context, name string, validation rest.ValidateObjectFunc, options *metav1.DeleteOptions) (kruntime.Object, bool, error) {
	fixture := &policyRetirementStorage{object: s.old.DeepCopyObject(), result: s.result}
	store := &registry.Store{
		NewFunc:                  func() kruntime.Object { return s.old.DeepCopyObject() },
		KeyFunc:                  func(_ context.Context, selected string) (string, error) { return selected, nil },
		DefaultQualifiedResource: schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: "policy"},
		DeleteStrategy:           s.strategy,
		EnableGarbageCollection:  true,
		Storage:                  registry.DryRunnableStorage{Storage: fixture},
	}
	obj, removed, err := store.Delete(ctx, name, validation, options)
	if err == nil && (!removed || fixture.object != nil) {
		return nil, false, fmt.Errorf("ordinary delete did not fully remove the fixture object")
	}
	return obj, removed, err
}

func policyRetirementRuntimeInfo() map[string]interface{} {
	value := policyChangeRuntimeInfo()
	value["kind"] = "rbac_policy_retirement_native_linkage"
	functions := value["functions"].(map[string]interface{})
	for label, function := range map[string]interface{}{
		"generic-delete": (*registry.Store).Delete,
		"before-delete":  rest.BeforeDelete,
		"delete-handler": handlers.DeleteResource,
	} {
		f := runtime.FuncForPC(reflect.ValueOf(function).Pointer())
		file, line := f.FileLine(f.Entry())
		functions[label] = map[string]interface{}{"function": f.Name(), "file": file, "line": line}
	}
	return value
}
