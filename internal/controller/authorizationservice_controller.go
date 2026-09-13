package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crcontroller "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	crsource "sigs.k8s.io/controller-runtime/pkg/source"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/engineclient"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/resources"
	"github.com/zcayou/k8s-authz/internal/source"
)

const (
	serviceCAIndex     = "authorization.zctx.io/service-ca"
	serviceSourceIndex = "authorization.zctx.io/service-source"

	secretKind    = "Secret"
	configMapKind = "ConfigMap"
)

// EngineClient is the engines' management API.
type EngineClient interface {
	Installed(context.Context, engineclient.Target) (engineclient.Installed, error)
	Replace(context.Context, engineclient.Target, []byte) error
	PutConditions(context.Context, engineclient.Target, condition.Module) error
}

// AuthorizationServiceReconciler compiles each service's policy, applies its
// owned objects and pushes the compiled state to its engines. It runs
// on the leader.
type AuthorizationServiceReconciler struct {
	// Client reads from the cache, except Secrets, which stay out of it.
	client.Client
	Programs *engine.Cache
	Sources  *source.Registry
	// EngineImage is the stock OPA image the engines run.
	EngineImage string
	// DecisionLogs has the engines log their decisions.
	DecisionLogs bool
	// ManagementRoots issues the operator's client certificate toward the engines,
	// which each engine's bootstrap names.
	ManagementRoots dynamiccertificates.CAContentProvider
	// ManagementCertificate is the operator's client certificate toward
	// the engines. Its Common Name is the management identity.
	ManagementCertificate *certwatcher.CertWatcher
	Engines               EngineClient
	// RemediationAfter is how long pushes to an engine pod may keep failing
	// before the pod is evicted.
	RemediationAfter time.Duration
	// Clock times how long pushes to each engine pod have kept failing.
	Clock    clock.PassiveClock
	Recorder events.EventRecorder

	mutex sync.Mutex
	// failing records, for each service, when pushes to each of its engine
	// pods started failing. It lives in the leader's memory, so a new leader
	// starts it afresh.
	failing map[types.NamespacedName]map[types.UID]time.Time
}

// +kubebuilder:rbac:groups=authorization.zctx.io,resources=authorizationservices,verbs=get;list;watch
// +kubebuilder:rbac:groups=authorization.zctx.io,resources=authorizationservices/status,verbs=patch
// +kubebuilder:rbac:groups=authorization.zctx.io,resources=authorizationservices/finalizers,verbs=update
// +kubebuilder:rbac:groups=authorization.zctx.io,resources=policysources,verbs=list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;patch
// +kubebuilder:rbac:groups="",resources=secrets;pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods/eviction,verbs=create
// +kubebuilder:rbac:groups=apps,resources=deployments;daemonsets,verbs=get;list;watch;create;patch;delete
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

func (r *AuthorizationServiceReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	var service api.AuthorizationService
	if err := r.Get(ctx, request.NamespacedName, &service); err != nil {
		if apierrors.IsNotFound(err) {
			r.forget(request.NamespacedName)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !service.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	config, err := decodeService(&service)
	if err != nil {
		return ctrl.Result{}, r.unprepared(ctx, &service, nil, err)
	}
	startupDigest, applyErr := r.applyOwned(ctx, &service)
	pending, err := r.unregisteredSource(ctx, &service)
	if err != nil {
		return ctrl.Result{}, errors.Join(applyErr, err)
	}
	if pending != nil {
		log.FromContext(ctx).V(1).Info("Waiting for PolicySource registration", "policySource", pending)
		waiting := fmt.Errorf("waiting for PolicySource %s to be registered", pending)
		return ctrl.Result{}, errors.Join(applyErr, r.writeStatus(ctx, &service, nil, 0, waiting))
	}
	identity := model.Identity{Namespace: service.Namespace, Name: service.Name, UID: string(service.UID)}
	prepared, err := r.Programs.Prepare(identity, config, r.Sources.Snapshot())
	if err != nil {
		return ctrl.Result{}, r.unprepared(ctx, &service, applyErr, err)
	}
	var current int32
	var pushErr error
	// Without a startup digest the owned objects couldn't be built, which
	// applyErr reports, and no pod can be known to have started from them.
	if startupDigest != "" {
		current, pushErr = r.reconcilePods(ctx, &service, startupDigest, prepared)
	}
	switchErr := r.finishRuntimeKindSwitch(ctx, &service)
	return ctrl.Result{}, errors.Join(applyErr, pushErr, switchErr, r.writeStatus(ctx, &service, &prepared, current, nil))
}

// unprepared writes the status of a service whose policy can't be prepared
// and returns failure as terminal: only a change to the spec or its sources,
// which reconciles the service again, can resolve it. When an earlier step
// or the status write failed, the error isn't terminal, so the reconcile
// is retried.
func (r *AuthorizationServiceReconciler) unprepared(ctx context.Context, service *api.AuthorizationService, earlier, failure error) error {
	if err := errors.Join(earlier, r.writeStatus(ctx, service, nil, 0, failure)); err != nil {
		return errors.Join(err, failure)
	}
	return reconcile.TerminalError(failure)
}

// forget drops what the reconciler holds for a deleted service: its compiled
// program and its engine pods' failure clock.
func (r *AuthorizationServiceReconciler) forget(service types.NamespacedName) {
	r.Programs.Forget(service.Namespace, service.Name)
	r.mutex.Lock()
	defer r.mutex.Unlock()
	delete(r.failing, service)
}

// apply server-side applies an owned object. The API server's single-controller
// rule refuses an object another controller owns.
func (r *AuthorizationServiceReconciler) apply(ctx context.Context, service *api.AuthorizationService, object runtime.ApplyConfiguration) error {
	if err := r.Apply(ctx, object, client.ForceOwnership); err != nil {
		r.Recorder.Eventf(service, nil, corev1.EventTypeWarning, "ApplyFailed", "Apply", "Could not apply owned object: %v", err)
		return err
	}
	return nil
}

func (r *AuthorizationServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	indexer := mgr.GetFieldIndexer()
	if err := indexer.IndexField(context.Background(), &api.AuthorizationService{}, serviceCAIndex, serviceCANames); err != nil {
		return fmt.Errorf("index AuthorizationService CA bundles: %w", err)
	}
	if err := indexer.IndexField(context.Background(), &api.AuthorizationService{}, serviceSourceIndex, serviceSourceNames); err != nil {
		return fmt.Errorf("index AuthorizationService PolicySources: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("authorizationservice").
		For(&api.AuthorizationService{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&corev1.ConfigMap{}).Owns(&appsv1.Deployment{}).Owns(&appsv1.DaemonSet{}).Owns(&corev1.Service{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		WatchesMetadata(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.servicesForSecret)).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.servicesForConfigMap)).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(servicesForPod)).
		WatchesRawSource(crsource.TypedFunc[reconcile.Request](r.registryEvents)).
		WatchesRawSource(crsource.TypedFunc[reconcile.Request](r.managementEvents)).
		WithOptions(crcontroller.Options{EnableWarmup: new(true), MaxConcurrentReconciles: 4}).
		Complete(r)
}

// serviceCANames indexes a service by the Secrets and ConfigMaps holding its
// client CA, which its engines start with, and its serving CA, which
// the operator verifies them against.
func serviceCANames(object client.Object) []string {
	service, ok := object.(*api.AuthorizationService)
	if !ok {
		return nil
	}
	return []string{caIndexKey(service.Spec.TLS.Server.CARef), caIndexKey(service.Spec.TLS.Client.CARef)}
}

func caIndexKey(ref api.CABundleRef) string {
	if ref.ConfigMapKeyRef != nil {
		return caObjectKey(configMapKind, ref.ConfigMapKeyRef.Name)
	}
	return caObjectKey(secretKind, ref.SecretKeyRef.Name)
}

func caObjectKey(kind, name string) string {
	return kind + "/" + name
}

// serviceSourceNames indexes a service by the PolicySources its endpoints
// read. The compiler rejects references outside them, so a source change
// affects only the services indexed under it.
func serviceSourceNames(object client.Object) []string {
	service, ok := object.(*api.AuthorizationService)
	if !ok {
		return nil
	}
	var names []string
	for _, endpoint := range service.Spec.Endpoints {
		for _, ref := range endpoint.SourceRefs {
			names = append(names, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}.String())
		}
	}
	return names
}

func (r *AuthorizationServiceReconciler) servicesForSecret(ctx context.Context, object client.Object) []ctrl.Request {
	return r.servicesMatching(ctx, client.InNamespace(object.GetNamespace()), client.MatchingFields{serviceCAIndex: caObjectKey(secretKind, object.GetName())})
}

func (r *AuthorizationServiceReconciler) servicesForConfigMap(ctx context.Context, object client.Object) []ctrl.Request {
	return r.servicesMatching(ctx, client.InNamespace(object.GetNamespace()), client.MatchingFields{serviceCAIndex: caObjectKey(configMapKind, object.GetName())})
}

// servicesForSource returns the services whose endpoints read the source.
func (r *AuthorizationServiceReconciler) servicesForSource(ctx context.Context, key model.SourceKey) []ctrl.Request {
	return r.servicesMatching(ctx, client.MatchingFields{serviceSourceIndex: types.NamespacedName{Namespace: key.Namespace, Name: key.Name}.String()})
}

func (r *AuthorizationServiceReconciler) servicesMatching(ctx context.Context, options ...client.ListOption) []ctrl.Request {
	var services api.AuthorizationServiceList
	if err := r.List(ctx, &services, options...); err != nil {
		log.FromContext(ctx).Error(err, "Could not list AuthorizationServices for a watch event")
		return nil
	}
	requests := make([]ctrl.Request, 0, len(services.Items))
	for index := range services.Items {
		requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&services.Items[index])})
	}
	return requests
}

// servicesForPod maps an engine pod to the service its instance label names.
func servicesForPod(_ context.Context, object client.Object) []ctrl.Request {
	name := object.GetLabels()[resources.LabelInstance]
	if name == "" {
		return nil
	}
	return []ctrl.Request{{NamespacedName: types.NamespacedName{Namespace: object.GetNamespace(), Name: name}}}
}

// managementEvents enqueues every service, whose engines all start from
// the management identity, when the management certificate or CA changes.
// The CA watcher runs on every replica, so a new leader starts from current
// roots.
func (r *AuthorizationServiceReconciler) managementEvents(ctx context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
	changed := func() {
		for _, request := range r.servicesMatching(ctx) {
			queue.Add(request)
		}
	}
	r.ManagementRoots.AddListener(listenerFunc(changed))
	r.ManagementCertificate.RegisterCallback(func(tls.Certificate) { changed() })
	return nil
}

// listenerFunc notifies of a CA bundle change.
type listenerFunc func()

func (f listenerFunc) Enqueue() {
	f()
}

// registryEvents enqueues the services that read each source whose registry
// state changes. Its cache List delays the registry's callbacks only while
// the caches sync at startup.
func (r *AuthorizationServiceReconciler) registryEvents(ctx context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
	r.Sources.Subscribe(func(key model.SourceKey) {
		for _, request := range r.servicesForSource(ctx, key) {
			queue.Add(request)
		}
	})
	return nil
}
