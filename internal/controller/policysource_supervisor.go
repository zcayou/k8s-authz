package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crcontroller "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/source"
	kubernetessource "github.com/zcayou/k8s-authz/internal/source/kubernetes"
	"github.com/zcayou/k8s-authz/internal/source/storage"
)

const policySourceKubeconfigIndex = "authorization.zctx.io/policy-source-kubeconfig"

// PolicySourceSupervisor keeps each PolicySource registered in the source
// registry on every replica. It holds no state of its own, changes only
// in-process registrations and never writes to the API server.
type PolicySourceSupervisor struct {
	// Client reads PolicySources from the cache.
	Client client.Client
	// APIReader reads kubeconfig Secrets and the persistent cache, which stay
	// out of the cache.
	APIReader   client.Reader
	Registry    *source.Registry
	LocalConfig *rest.Config
}

// +kubebuilder:rbac:groups=authorization.zctx.io,resources=policysources,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=authorization.zctx.io,resources=policies;policybindings;policysets,verbs=list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings;clusterroles;clusterrolebindings,verbs=list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=list;watch
// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,resourceNames=policies.authorization.zctx.io;policybindings.authorization.zctx.io;policysets.authorization.zctx.io,verbs=list;watch

// Reconcile registers a PolicySource, or removes a deleted one. Until
// the registry holds the PolicySource's UID, it first restores the view
// cached for that UID, so the source is never registered without it.
func (s *PolicySourceSupervisor) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	key := model.SourceKey{Namespace: request.Namespace, Name: request.Name}
	var object api.PolicySource
	if err := s.Client.Get(ctx, request.NamespacedName, &object); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("read PolicySource %s: %w", request.NamespacedName, err)
		}
		s.Registry.Remove(key)
		return ctrl.Result{}, nil
	}
	if !object.DeletionTimestamp.IsZero() {
		s.Registry.Remove(key)
		return ctrl.Result{}, nil
	}
	collection := kubernetessource.NewCollection(object.Spec)
	instance := model.SourceInstance{Key: key, UID: string(object.UID)}
	if object.Spec.Synchronization == api.SynchronizationPaused {
		if err := s.restore(ctx, instance); err != nil {
			return ctrl.Result{}, err
		}
		s.Registry.Pause(key, instance.UID, sourceSettings(object.Spec), collection)
		return ctrl.Result{}, nil
	}
	connection, err := s.connect(ctx, &object, collection)
	if err != nil {
		return ctrl.Result{}, err
	}
	instance.Origin = connection.origin
	if err := s.restore(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}
	registration := source.Registration{Instance: instance, Coverage: collection, Digest: connection.digest, Settings: sourceSettings(object.Spec)}
	return ctrl.Result{}, s.Registry.Apply(registration, func() (source.Reader, error) {
		if connection.err != nil {
			return nil, connection.err
		}
		return newReader(connection.configuration, instance, collection)
	})
}

// sourceSettings resolves the PolicySource's settings. A source with rego
// and no allowedBuiltins allows the default builtins. Names this release
// doesn't define are kept: they allow nothing, and a condition calling one
// reports BuiltinNotAllowed.
func sourceSettings(spec api.PolicySourceSpec) source.Settings {
	settings := source.Settings{Contribution: spec.Contribution}
	switch {
	case spec.Rego == nil:
	case spec.Rego.AllowedBuiltins == nil:
		settings.AllowedBuiltins = new(condition.DefaultBuiltins())
	default:
		settings.AllowedBuiltins = new(model.NewBuiltinSet(spec.Rego.AllowedBuiltins))
	}
	return settings
}

// restore seeds the registry with the view cached for instance's UID unless
// the registry already holds that UID. An instance without an origin accepts
// the origin the cache recorded.
func (s *PolicySourceSupervisor) restore(ctx context.Context, instance model.SourceInstance) error {
	if uid, _ := s.Registry.Registered(instance.Key); uid == instance.UID {
		return nil
	}
	view, found, err := storage.Read(ctx, s.APIReader, instance)
	if err != nil {
		return err
	}
	if found {
		s.Registry.Restore(view)
	}
	return nil
}

type policySourceConnection struct {
	configuration *rest.Config
	// origin is empty when the credential is unusable.
	origin string
	// digest covers the kubeconfig and the collection, including whether
	// it reads namespace labels.
	digest string
	// err is a credential problem, which the registry records.
	err error
}

// connect resolves the source's API server connection. It returns an error
// only when the kubeconfig Secret couldn't be read.
func (s *PolicySourceSupervisor) connect(ctx context.Context, policySource *api.PolicySource, collection kubernetessource.Collection) (policySourceConnection, error) {
	if policySource.Spec.Provider.Kubernetes == nil || policySource.Spec.Provider.Kubernetes.Kubeconfig == nil {
		origin, err := kubernetessource.Origin(s.LocalConfig)
		if err != nil {
			return policySourceConnection{}, err
		}
		return policySourceConnection{configuration: s.LocalConfig, origin: origin, digest: connectionDigest(collection, nil)}, nil
	}
	ref := policySource.Spec.Provider.Kubernetes.Kubeconfig.SecretRef
	secret := &corev1.Secret{}
	key := types.NamespacedName{Namespace: policySource.Namespace, Name: ref.Name}
	if err := s.APIReader.Get(ctx, key, secret); client.IgnoreNotFound(err) != nil {
		return policySourceConnection{}, fmt.Errorf("read kubeconfig Secret %s: %w", key, err)
	}
	data := secret.Data[ref.Key]
	connection := policySourceConnection{digest: connectionDigest(collection, data)}
	switch {
	case secret.UID == "" || !secret.DeletionTimestamp.IsZero():
		connection.err = fmt.Errorf("kubeconfig Secret %s is missing", key)
	case len(data) == 0:
		connection.err = fmt.Errorf("kubeconfig Secret %s does not contain nonempty key %q", key, ref.Key)
	default:
		connection.configuration, connection.err = kubernetessource.ParseKubeconfig(data)
	}
	if connection.err == nil {
		connection.origin, connection.err = kubernetessource.Origin(connection.configuration)
	}
	return connection, nil
}

func connectionDigest(collection kubernetessource.Collection, kubeconfig []byte) string {
	return model.Digest(struct {
		Collection kubernetessource.Collection `json:"collection"`
		Kubeconfig []byte                      `json:"kubeconfig"`
	}{collection, kubeconfig})
}

func newReader(configuration *rest.Config, instance model.SourceInstance, collection kubernetessource.Collection) (source.Reader, error) {
	configuration = rest.CopyConfig(configuration)
	configuration.UserAgent = "k8s-authz-source-reader"
	sourceClient, err := dynamic.NewForConfig(configuration)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes dynamic client: %w", err)
	}
	return kubernetessource.NewReader(sourceClient, instance, collection), nil
}

func policySourceSecretNames(object client.Object) []string {
	policySource, ok := object.(*api.PolicySource)
	if !ok || policySource.Spec.Provider.Kubernetes == nil || policySource.Spec.Provider.Kubernetes.Kubeconfig == nil {
		return nil
	}
	return []string{policySource.Spec.Provider.Kubernetes.Kubeconfig.SecretRef.Name}
}

func (s *PolicySourceSupervisor) policySourcesForSecret(ctx context.Context, object client.Object) []ctrl.Request {
	var list api.PolicySourceList
	if err := s.Client.List(ctx, &list, client.InNamespace(object.GetNamespace()), client.MatchingFields{policySourceKubeconfigIndex: object.GetName()}); err != nil {
		log.FromContext(ctx).Error(err, "Could not map Secret to PolicySources", "secret", client.ObjectKeyFromObject(object))
		return nil
	}
	requests := make([]ctrl.Request, 0, len(list.Items))
	for index := range list.Items {
		requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[index])})
	}
	return requests
}

// SetupWithManager runs the supervisor on every replica.
func (s *PolicySourceSupervisor) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &api.PolicySource{}, policySourceKubeconfigIndex, policySourceSecretNames); err != nil {
		return fmt.Errorf("index PolicySource kubeconfig Secrets: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("policysource-supervisor").
		For(&api.PolicySource{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		WatchesMetadata(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(s.policySourcesForSecret)).
		WithOptions(crcontroller.Options{NeedLeaderElection: new(false)}).
		Complete(s)
}
