package kubernetes_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/source/kubernetes"
)

const teamNamespace = "team"

var source = model.SourceInstance{Key: model.SourceKey{Namespace: "control", Name: "local"}, UID: "source-uid", Origin: "https://control.example"}

var listKinds = map[schema.GroupVersionResource]string{
	{Group: api.GroupVersion.Group, Version: "v1alpha1", Resource: "policies"}:            "PolicyList",
	{Group: api.GroupVersion.Group, Version: "v1alpha1", Resource: "policybindings"}:      "PolicyBindingList",
	{Group: api.GroupVersion.Group, Version: "v1alpha1", Resource: "policysets"}:          "PolicySetList",
	{Group: rbacv1.GroupName, Version: "v1", Resource: "roles"}:                           "RoleList",
	{Group: rbacv1.GroupName, Version: "v1", Resource: "rolebindings"}:                    "RoleBindingList",
	{Group: rbacv1.GroupName, Version: "v1", Resource: "clusterroles"}:                    "ClusterRoleList",
	{Group: rbacv1.GroupName, Version: "v1", Resource: "clusterrolebindings"}:             "ClusterRoleBindingList",
	{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}: "CustomResourceDefinitionList",
}

func fakeClient(objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...)
}

// policyCRD returns the Policy CRD, serving this API version when served.
func policyCRD(served bool) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
		"metadata": map[string]any{"name": "policies." + api.GroupVersion.Group},
		"spec":     map[string]any{"versions": []any{map[string]any{"name": api.GroupVersion.Version, "served": served}}},
	}}
}

func policy(name string, spec map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": api.GroupVersion.String(), "kind": model.KindPolicy,
		"metadata": map[string]any{"namespace": teamNamespace, "name": name, "uid": name + "-uid"},
		"spec":     spec,
	}}
}

func allowPods() map[string]any {
	return map[string]any{"include": []any{map[string]any{"apiGroups": []any{""}, "resources": []any{"pods"}, "verbs": []any{"get"}, "namespaces": []any{"*"}}}}
}

// run runs reader until the spec ends and delivers what it emits.
func run(ctx context.Context, reader *kubernetes.Reader) <-chan model.SourceObservation {
	observations := make(chan model.SourceObservation, 16)
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader.Run(ctx, func(observation model.SourceObservation) {
			select {
			case observations <- observation:
			case <-ctx.Done():
			}
		})
	}()
	DeferCleanup(func() {
		cancel()
		Eventually(done).Should(BeClosed())
	})
	return observations
}

func collection(kinds []string, namespaces []string, names ...string) api.KeyRange {
	return api.KeyRange{Kinds: kinds, Namespaces: namespaces, Names: names}
}
