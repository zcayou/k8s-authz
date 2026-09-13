package operator

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/zcayou/k8s-authz/internal/diagnostics"
)

// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create

// setupDiagnostics adds the diagnostics endpoint to mgr on every replica.
// It serves options.DiagnosticsBindAddress with the certificate
// in options.DiagnosticsCertPath, and delegates authentication
// and authorization to the API server as controller-runtime's metrics filter
// does, through mgr's config and HTTP client.
func setupDiagnostics(mgr manager.Manager, options Options, backend diagnostics.Backend) error {
	certificate, err := certwatcher.New(certificateFiles(options.DiagnosticsCertPath))
	if err != nil {
		return fmt.Errorf("load diagnostics certificate: %w", err)
	}
	clientset, err := kubernetes.NewForConfigAndClient(mgr.GetConfig(), mgr.GetHTTPClient())
	if err != nil {
		return fmt.Errorf("create Kubernetes clientset: %w", err)
	}
	// The API server publishes the CA that issues its users' client certificates
	// here, as it does for every delegating API server.
	clientCA, err := dynamiccertificates.NewDynamicCAFromConfigMapController("diagnostics-client-ca", metav1.NamespaceSystem, "extension-apiserver-authentication", "client-ca-file", clientset)
	if err != nil {
		return fmt.Errorf("create diagnostics client CA controller: %w", err)
	}
	backoff := &wait.Backoff{Duration: 500 * time.Millisecond, Factor: 1.5, Jitter: 0.2, Steps: 5}
	authentication, _, err := authenticatorfactory.DelegatingAuthenticatorConfig{
		Anonymous:                          &apiserver.AnonymousAuthConfig{Enabled: false},
		TokenAccessReviewClient:            clientset.AuthenticationV1(),
		TokenAccessReviewTimeout:           10 * time.Second,
		WebhookRetryBackoff:                backoff,
		CacheTTL:                           time.Minute,
		ClientCertificateCAContentProvider: clientCA,
	}.New()
	if err != nil {
		return fmt.Errorf("create diagnostics authenticator: %w", err)
	}
	authorization, err := authorizerfactory.DelegatingAuthorizerConfig{
		SubjectAccessReviewClient: clientset.AuthorizationV1(),
		AllowCacheTTL:             time.Minute,
		DenyCacheTTL:              10 * time.Second,
		WebhookRetryBackoff:       backoff,
	}.New()
	if err != nil {
		return fmt.Errorf("create diagnostics authorizer: %w", err)
	}
	listener, err := tls.Listen("tcp", options.DiagnosticsBindAddress, &tls.Config{
		MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert,
		GetCertificate: certificate.GetCertificate, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		return fmt.Errorf("listen for diagnostics: %w", err)
	}
	server := &manager.Server{
		Name: "diagnostics",
		Server: &http.Server{
			Handler:           diagnostics.NewHandler(mgr.GetLogger().WithName("diagnostics"), authentication, authorization, backend),
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute,
			MaxHeaderBytes: 16 << 10,
		},
		Listener:        listener,
		ShutdownTimeout: new(5 * time.Second),
	}
	for name, runnable := range map[string]manager.Runnable{
		"diagnostics certificate watcher": certificate,
		"diagnostics client CA controller": everyReplica(func(ctx context.Context) error {
			clientCA.Run(ctx, 1)
			return nil
		}),
		"diagnostics server": server,
	} {
		if err = mgr.Add(runnable); err != nil {
			return fmt.Errorf("add %s: %w", name, err)
		}
	}
	return nil
}
