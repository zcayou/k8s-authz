package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
)

// unregisteredSource returns a PolicySource the service's endpoints read
// that exists, isn't being deleted, and isn't registered in the source registry
// under its UID, so its view, including one restored from the persistent cache,
// may be missing from the registry's snapshot. The registration notifies
// the services that read the source. The endpoints' sourceRefs bound what
// a compilation reads. A source that isn't in the cache, because it doesn't
// exist or lies outside the control namespaces, compiles as unavailable.
func (r *AuthorizationServiceReconciler) unregisteredSource(ctx context.Context, service *api.AuthorizationService) (*types.NamespacedName, error) {
	required := sets.New[model.SourceKey]()
	for _, endpoint := range service.Spec.Endpoints {
		for _, ref := range endpoint.SourceRefs {
			required.Insert(model.SourceKey{Namespace: ref.Namespace, Name: ref.Name})
		}
	}
	var sources api.PolicySourceList
	if err := r.List(ctx, &sources); err != nil {
		return nil, fmt.Errorf("list PolicySources: %w", err)
	}
	for index := range sources.Items {
		object := &sources.Items[index]
		key := model.SourceKey{Namespace: object.Namespace, Name: object.Name}
		if !required.Has(key) || !object.DeletionTimestamp.IsZero() {
			continue
		}
		if uid, _ := r.Sources.Registered(key); uid != string(object.UID) {
			return &types.NamespacedName{Namespace: key.Namespace, Name: key.Name}, nil
		}
	}
	return nil, nil
}
