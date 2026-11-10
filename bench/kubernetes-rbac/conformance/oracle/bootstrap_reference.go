package main

// This explicit excerpt is generated from the pinned upstream bootstrap policy.
// It is an assumed input for offline examples, not an observed cluster inventory
// or the complete bootstrap catalog. No default bindings are added.
import (
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac/bootstrappolicy"
)

func selectBootstrapRoles(namespaceRoles map[string][]rbacv1.Role, clusterRoles []rbacv1.ClusterRole) ([]runtime.Object, error) {
	var roles []*rbacv1.Role
	for _, role := range namespaceRoles["kube-system"] {
		if role.Name == "extension-apiserver-authentication-reader" {
			if role.Namespace != "kube-system" {
				return nil, fmt.Errorf("bootstrap reference role has unexpected namespace %q", role.Namespace)
			}
			roles = append(roles, role.DeepCopy())
		}
	}
	var clusters []*rbacv1.ClusterRole
	for _, role := range clusterRoles {
		if role.Name == "system:auth-delegator" {
			if role.Namespace != "" {
				return nil, fmt.Errorf("bootstrap reference ClusterRole has namespace %q", role.Namespace)
			}
			clusters = append(clusters, role.DeepCopy())
		}
	}
	if len(roles) != 1 || len(clusters) != 1 {
		return nil, fmt.Errorf("expected one authentication-reader Role and one auth-delegator ClusterRole; got %d and %d", len(roles), len(clusters))
	}
	return []runtime.Object{roles[0], clusters[0]}, nil
}

func bootstrapReference() ([]byte, error) {
	objects, err := selectBootstrapRoles(bootstrappolicy.NamespaceRoles(), bootstrappolicy.ClusterRoles())
	if err != nil {
		return nil, err
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, rbacv1.AddToScheme} {
		if err := add(scheme); err != nil {
			return nil, err
		}
	}
	codecs := serializer.NewCodecFactory(scheme)
	rbacCodec := codecs.LegacyCodec(rbacv1.SchemeGroupVersion)
	list := &corev1.List{Items: make([]runtime.RawExtension, 0, len(objects))}
	for _, object := range objects {
		// The registered upstream codec supplies each object's GVK. RawExtension
		// then retains the entire serialized object inside the v1/List.
		encoded, err := runtime.Encode(rbacCodec, object)
		if err != nil {
			return nil, err
		}
		list.Items = append(list.Items, runtime.RawExtension{Raw: encoded})
	}
	return runtime.Encode(codecs.LegacyCodec(corev1.SchemeGroupVersion), list)
}

func bootstrapReferenceFiles(args []string) {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: rbac-oracle --bootstrap-reference")
		os.Exit(2)
	}
	data, err := bootstrapReference()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(data); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
