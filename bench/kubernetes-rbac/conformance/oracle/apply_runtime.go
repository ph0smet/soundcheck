package main

import (
	"reflect"
	"runtime"
	"runtime/debug"

	"k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/handlers"
	registry "k8s.io/apiserver/pkg/registry/generic/registry"
)

// Record the linked native implementations as well as the checked disk source
// hashes. This makes accidentally replacing the handler/store by local callback
// selection visible in the reference receipt.
func applyRuntimeInfo() map[string]interface{} {
	functions := map[string]interface{}{
		"request-info":          filters.WithRequestInfo,
		"authorization-filter":  filters.WithAuthorization,
		"patch-handler":         handlers.PatchResource,
		"generic-store-update":  (*registry.Store).Update,
		"native-dry-run-update": (*registry.DryRunnableStorage).GuaranteedUpdate,
	}
	links := map[string]interface{}{}
	add := func(label string, value reflect.Value) {
		f := runtime.FuncForPC(value.Pointer())
		file, line := f.FileLine(f.Entry())
		links[label] = map[string]interface{}{"function": f.Name(), "file": file, "line": line}
	}
	for label, function := range functions {
		add(label, reflect.ValueOf(function))
	}
	for _, target := range [][2]string{{"configmaps", ""}, {"secrets", ""}, {"pods", ""}, {"services", ""}, {"endpoints", ""}, {"nodes", ""}, {"deployments", "apps"}, {"endpointslices", "discovery.k8s.io"}} {
		_, _, _, strategy, err := applyFixture(applyRequest{Resource: target[0], APIGroup: target[1], Name: "fixture", Namespace: "demo"})
		if err != nil {
			panic(err)
		}
		method, ok := reflect.TypeOf(strategy).MethodByName("AllowCreateOnUpdate")
		if !ok {
			panic("native strategy method missing")
		}
		add("strategy-"+target[0], method.Func)
	}
	modules := map[string]string{}
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, dependency := range info.Deps {
			path, version := dependency.Path, dependency.Version
			if dependency.Replace != nil {
				path, version = dependency.Replace.Path, dependency.Replace.Version
			}
			modules[path] = version
		}
	}
	return map[string]interface{}{"schema_version": 1, "kind": "rbac_apply_native_linkage", "go_version": runtime.Version(), "modules": modules, "functions": links}
}
