//go:build integration

package integration

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/zcayou/k8s-authz/internal/operator"
	"github.com/zcayou/k8s-authz/test/utils"
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Suite")
}

var _ = BeforeSuite(func(ctx SpecContext) {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
	var err error
	testEnv, err = newEnvironment()
	Expect(err).NotTo(HaveOccurred())
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { Expect(testEnv.Stop()).To(Succeed()) })
	// The remote API server stops after the manager, whose readers watch it.
	DeferCleanup(stopRemoteEnvironment)
	scheme, err := utils.Scheme()
	Expect(err).NotTo(HaveOccurred())
	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace}})).To(Succeed())

	engines = utils.NewFakeEngines()
	management, err := utils.WriteTLSFiles(GinkgoT().TempDir())
	Expect(err).NotTo(HaveOccurred())
	managementCAPath = management.Authority
	diagnosticsCertificates := GinkgoT().TempDir()
	diagnosticsTLS, err := utils.WriteTLSFiles(diagnosticsCertificates, "127.0.0.1")
	Expect(err).NotTo(HaveOccurred())
	diagnosticsCAPath = diagnosticsTLS.Authority
	options := operator.Options{
		EngineImage:            engineImage,
		ManagementCertPath:     filepath.Dir(management.Certificate),
		ManagementCAPath:       management.Authority,
		DiagnosticsBindAddress: freeAddresses(ctx, 1)[0],
		DiagnosticsCertPath:    diagnosticsCertificates,
	}
	diagnosticsAddress = options.DiagnosticsBindAddress
	managerOptions := operator.ManagerOptions(scheme, options)
	managerOptions.Metrics = metricsserver.Options{BindAddress: "0"}
	managerOptions.HealthProbeBindAddress = "0"
	managerOptions.LeaderElection = true
	managerOptions.LeaderElectionNamespace = operatorNamespace
	mgr, err := ctrl.NewManager(cfg, managerOptions)
	Expect(err).NotTo(HaveOccurred())
	Expect(operator.Setup(mgr, options, engines)).To(Succeed())
	running, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- mgr.Start(running) }()
	DeferCleanup(func() {
		cancel()
		Eventually(stopped).WithTimeout(15 * time.Second).Should(Receive(Succeed()))
	})
})
