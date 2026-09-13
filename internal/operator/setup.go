package operator

import (
	"context"
	"crypto/tls"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/zcayou/k8s-authz/internal/controller"
	"github.com/zcayou/k8s-authz/internal/diagnostics"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/engineclient"
	"github.com/zcayou/k8s-authz/internal/resources"
	"github.com/zcayou/k8s-authz/internal/source"
)

// Engines is the engines' management API: the leader's pushes
// and the diagnostics endpoint's snapshot reads.
type Engines interface {
	controller.EngineClient
	diagnostics.Engines
}

// ManagerOptions returns the manager options the operator needs: its
// namespaces, a Pod cache holding only engine pods, Secrets read without
// a cache, and resources.FieldOwner as the client's field owner.
func ManagerOptions(scheme *runtime.Scheme, options Options) ctrl.Options {
	var namespaces map[string]cache.Config
	if len(options.ControlNamespaces) != 0 {
		namespaces = make(map[string]cache.Config, len(options.ControlNamespaces))
		for _, namespace := range options.ControlNamespaces {
			namespaces[namespace] = cache.Config{}
		}
	}
	return ctrl.Options{
		Scheme: scheme,
		Cache: cache.Options{
			DefaultNamespaces: namespaces,
			ByObject:          map[client.Object]cache.ByObject{&corev1.Pod{}: {Label: resources.EngineSelector()}},
		},
		Client: client.Options{
			Cache:      &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}}},
			FieldOwner: resources.FieldOwner,
		},
		LeaderElectionID:              "6e2fcf72.zctx.io",
		LeaderElectionReleaseOnCancel: true,
	}
}

// Setup adds the source registry and supervisor, the diagnostics endpoint
// and the management certificate and CA watchers, which run on every replica,
// and the leader's PolicySource and AuthorizationService controllers.
// A nil engines builds the engine management client from the management
// certificate.
func Setup(mgr ctrl.Manager, options Options, engines Engines) error {
	certificate, err := certwatcher.New(certificateFiles(options.ManagementCertPath))
	if err != nil {
		return fmt.Errorf("load management certificate: %w", err)
	}
	roots, err := dynamiccertificates.NewDynamicCAContentFromFile("management-ca", options.ManagementCAPath)
	if err != nil {
		return fmt.Errorf("load management CA: %w", err)
	}
	if engines == nil {
		engines = engineclient.New(func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return certificate.GetCertificate(nil) })
	}
	registry := source.NewRegistry()
	supervisor := &controller.PolicySourceSupervisor{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Registry: registry, LocalConfig: mgr.GetConfig()}
	sources := &controller.PolicySourceReconciler{Client: mgr.GetClient(), Cache: mgr.GetCache(), Registry: registry}
	authorization := &controller.AuthorizationServiceReconciler{
		Client: mgr.GetClient(), Programs: engine.NewCache(), Sources: registry,
		EngineImage: options.EngineImage, DecisionLogs: options.EngineDecisionLogs,
		ManagementRoots: roots, ManagementCertificate: certificate, Engines: engines,
		RemediationAfter: options.RemediationAfter, Clock: clock.RealClock{}, Recorder: mgr.GetEventRecorder("authorizationservice"),
	}
	if err = supervisor.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up PolicySource supervisor: %w", err)
	}
	if err = sources.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up PolicySource controller: %w", err)
	}
	if err = authorization.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up AuthorizationService controller: %w", err)
	}
	backend := diagnostics.Backend{Reader: mgr.GetClient(), Namespaces: options.ControlNamespaces, Target: authorization.EngineTarget, Engines: engines}
	if err = setupDiagnostics(mgr, options, backend); err != nil {
		return fmt.Errorf("set up diagnostics: %w", err)
	}
	if err = mgr.Add(registry); err != nil {
		return fmt.Errorf("add source registry: %w", err)
	}
	if err = mgr.Add(certificate); err != nil {
		return fmt.Errorf("add management certificate watcher: %w", err)
	}
	if err = mgr.Add(everyReplica(func(ctx context.Context) error {
		roots.Run(ctx, 1)
		return nil
	})); err != nil {
		return fmt.Errorf("add management CA watcher: %w", err)
	}
	return nil
}

// everyReplica runs on every replica, leader or not.
type everyReplica manager.RunnableFunc

func (r everyReplica) Start(ctx context.Context) error {
	return r(ctx)
}

func (everyReplica) NeedLeaderElection() bool {
	return false
}
