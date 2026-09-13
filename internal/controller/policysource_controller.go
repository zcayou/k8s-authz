/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crcontroller "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	crsource "sigs.k8s.io/controller-runtime/pkg/source"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	apiac "github.com/zcayou/k8s-authz/api/v1alpha1/applyconfiguration/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/source"
	"github.com/zcayou/k8s-authz/internal/source/storage"
)

// PolicySourceReconciler projects each source's registry health into its
// status and writes its view to the persistent cache. It runs on the leader.
type PolicySourceReconciler struct {
	// Client reads PolicySources from the cache and writes cache Secrets.
	client.Client
	// Cache reads the metadata of cache Secrets, whose contents stay out
	// of the cache.
	Cache    client.Reader
	Registry *source.Registry
}

// +kubebuilder:rbac:groups=authorization.zctx.io,resources=policysources,verbs=get;list;watch
// +kubebuilder:rbac:groups=authorization.zctx.io,resources=policysources/status,verbs=patch
// +kubebuilder:rbac:groups=authorization.zctx.io,resources=policysources/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=list;watch;create;patch;delete

// Reconcile writes a source's status and persists its view once the registry
// holds the PolicySource's UID, so a recreated PolicySource never inherits its
// former incarnation's health or view. The registration notifies.
func (r *PolicySourceReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	var object api.PolicySource
	if err := r.Get(ctx, request.NamespacedName, &object); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("read PolicySource %s: %w", request.NamespacedName, err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	key := model.SourceKey{Namespace: request.Namespace, Name: request.Name}
	if uid, _ := r.Registry.Registered(key); uid != string(object.UID) {
		return ctrl.Result{}, nil
	}
	view := r.Registry.Effective(key)
	configuration := apiac.PolicySource(object.Name, object.Namespace).WithStatus(r.projectStatus(&object, view))
	if err := applyStatus(ctx, r.Client, configuration); err != nil {
		return ctrl.Result{}, fmt.Errorf("apply PolicySource %s status: %w", request.NamespacedName, err)
	}
	return ctrl.Result{}, r.persist(ctx, &object, view)
}

// persist writes a complete view to the source's cache unless the cache
// already holds it.
func (r *PolicySourceReconciler) persist(ctx context.Context, policySource *api.PolicySource, view model.SourceObservation) error {
	if !view.Complete {
		return nil
	}
	return storage.Write(ctx, r.Client, r.Cache, policySource, view)
}

// projectStatus returns the source's status projected from its registry
// health. lastAdmittedTime keeps its stored value while the registry has no
// admission time, as after a view is restored.
func (r *PolicySourceReconciler) projectStatus(policySource *api.PolicySource, view model.SourceObservation) *apiac.PolicySourceStatusApplyConfiguration {
	key := model.SourceKey{Namespace: policySource.Namespace, Name: policySource.Name}
	status := apiac.PolicySourceStatus().WithObservedGeneration(policySource.Generation)
	health := r.Registry.Health(key)
	switch {
	case !health.LastAdmitted.IsZero():
		status.WithLastAdmittedTime(metav1.Time{Time: health.LastAdmitted})
	case policySource.Status.LastAdmittedTime != nil:
		status.WithLastAdmittedTime(*policySource.Status.LastAdmittedTime)
	}
	synchronized := func(state metav1.ConditionStatus, reason, message string) {
		status.WithConditions(statusCondition(policySource.Status.Conditions, policySource.Generation, api.ConditionSynchronized, state, reason, message))
	}
	switch {
	case health.Complete:
		synchronized(metav1.ConditionTrue, api.ReasonSynchronized, "the latest acquisition is complete")
	case health.Reason == api.ReasonPending:
		synchronized(metav1.ConditionUnknown, health.Reason, health.Message)
	default:
		synchronized(metav1.ConditionFalse, health.Reason, health.Message)
	}
	var issues []model.Issue
	for _, document := range view.Documents {
		issues = append(issues, document.Issues...)
	}
	converted, truncated := statusIssues(issues)
	status.WithIssues(converted...)
	if truncated {
		status.WithIssuesTruncated(true)
	}
	return status
}

// registryEvents enqueues each PolicySource whose registry state changes.
func (r *PolicySourceReconciler) registryEvents(_ context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
	r.Registry.Subscribe(func(key model.SourceKey) {
		queue.Add(reconcile.Request{NamespacedName: types.NamespacedName{Namespace: key.Namespace, Name: key.Name}})
	})
	return nil
}

// SetupWithManager runs the reconciler on the leader, with its cache warm
// on every replica. It watches the metadata of the cache Secrets each
// PolicySource controls, so a chunk deleted or relabeled out of band
// is rewritten.
func (r *PolicySourceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("policysource").
		For(&api.PolicySource{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&corev1.Secret{}, builder.OnlyMetadata, builder.WithPredicates(predicate.Or[client.Object](predicate.LabelChangedPredicate{}, predicate.AnnotationChangedPredicate{}))).
		WatchesRawSource(crsource.TypedFunc[reconcile.Request](r.registryEvents)).
		WithOptions(crcontroller.Options{EnableWarmup: new(true)}).
		Complete(r)
}
