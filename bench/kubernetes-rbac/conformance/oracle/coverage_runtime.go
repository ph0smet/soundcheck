package main

import (
	"reflect"
	"runtime"

	"k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/handlers"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/kubernetes/pkg/registry/apps/daemonset"
	"k8s.io/kubernetes/pkg/registry/apps/replicaset"
	"k8s.io/kubernetes/pkg/registry/apps/statefulset"
	"k8s.io/kubernetes/pkg/registry/batch/cronjob"
	"k8s.io/kubernetes/pkg/registry/batch/job"
	"k8s.io/kubernetes/pkg/registry/coordination/lease"
	"k8s.io/kubernetes/pkg/registry/core/event"
	"k8s.io/kubernetes/pkg/registry/core/namespace"
	"k8s.io/kubernetes/pkg/registry/core/persistentvolume"
	"k8s.io/kubernetes/pkg/registry/core/persistentvolumeclaim"
	"k8s.io/kubernetes/pkg/registry/core/serviceaccount"
	"k8s.io/kubernetes/pkg/registry/networking/ingress"
	"k8s.io/kubernetes/pkg/registry/networking/ingressclass"
	"k8s.io/kubernetes/pkg/registry/storage/storageclass"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
)

func coverageRuntimeInfo() map[string]interface{} {
	info := applyRuntimeInfo()
	info["kind"] = "rbac_coverage_native_linkage"
	// These are real strategy methods, not copied scope booleans. Namespace
	// object scope is cluster-wide even though its named URL sets Namespace.
	info["resource_scopes"] = map[string]bool{
		"serviceaccounts":                  serviceaccount.Strategy.NamespaceScoped(),
		"events":                           event.Strategy.NamespaceScoped(),
		"events.events.k8s.io":             event.Strategy.NamespaceScoped(),
		"namespaces":                       namespace.Strategy.NamespaceScoped(),
		"persistentvolumeclaims":           persistentvolumeclaim.Strategy.NamespaceScoped(),
		"persistentvolumes":                persistentvolume.Strategy.NamespaceScoped(),
		"replicasets.apps":                 replicaset.Strategy.NamespaceScoped(),
		"statefulsets.apps":                statefulset.Strategy.NamespaceScoped(),
		"daemonsets.apps":                  daemonset.Strategy.NamespaceScoped(),
		"jobs.batch":                       job.Strategy.NamespaceScoped(),
		"cronjobs.batch":                   cronjob.Strategy.NamespaceScoped(),
		"leases.coordination.k8s.io":       lease.Strategy.NamespaceScoped(),
		"ingresses.networking.k8s.io":      ingress.Strategy.NamespaceScoped(),
		"ingressclasses.networking.k8s.io": ingressclass.Strategy.NamespaceScoped(),
		"storageclasses.storage.k8s.io":    storageclass.Strategy.NamespaceScoped(),
	}
	links := info["functions"].(map[string]interface{})
	for label, function := range map[string]interface{}{
		"update-handler":        handlers.UpdateResource,
		"authorizer-attributes": filters.GetAuthorizerAttributes,
		"request-classifier":    (*apirequest.RequestInfoFactory).NewRequestInfo,
		"rbac-authorizer":       (*rbacauthorizer.RBACAuthorizer).Authorize,
	} {
		f := runtime.FuncForPC(reflect.ValueOf(function).Pointer())
		file, line := f.FileLine(f.Entry())
		links[label] = map[string]interface{}{"function": f.Name(), "file": file, "line": line}
	}
	return info
}
