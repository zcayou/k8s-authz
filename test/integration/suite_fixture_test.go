//go:build integration

package integration

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/zcayou/k8s-authz/test/utils"
)

const (
	// engineImage is the digest-pinned engine image the operator runs.
	engineImage = "example/engine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// convergence bounds how long a spec waits for the operator to react.
	convergence = 20 * time.Second
	// operatorNamespace holds the manager's leader election lease.
	operatorNamespace = "k8s-authz-system"
)

var (
	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient client.Client
	engines   *utils.FakeEngines
	// managementCAPath is the operator's management CA bundle file.
	managementCAPath string
	// diagnosticsAddress is where the diagnostics endpoint listens. Its
	// certificate for 127.0.0.1 chains to the CA in diagnosticsCAPath.
	diagnosticsAddress, diagnosticsCAPath string
)

var remoteEnvironment *envtest.Environment

// remoteAPI starts the second API server the multi-API specs read a remote
// source from, once, and returns its admin configuration.
var remoteAPI = sync.OnceValues(func() (*rest.Config, error) {
	environment, err := newEnvironment()
	if err != nil {
		return nil, err
	}
	config, err := environment.Start()
	if err != nil {
		return nil, err
	}
	remoteEnvironment = environment
	return config, nil
})

func stopRemoteEnvironment() {
	if remoteEnvironment != nil {
		Expect(remoteEnvironment.Stop()).To(Succeed())
	}
}

// newNamespace creates a namespace for one spec. envtest runs no namespace
// controller, so a deleted namespace would keep its objects; specs delete
// the objects the operator acts on instead.
func newNamespace(ctx context.Context, prefix string) string {
	GinkgoHelper()
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: prefix + "-"}}
	Expect(k8sClient.Create(ctx, namespace)).To(Succeed())
	return namespace.Name
}

// authority returns a new self-signed CA.
func authority() utils.Material {
	GinkgoHelper()
	material, err := utils.NewAuthority(time.Now())
	Expect(err).NotTo(HaveOccurred())
	return material
}

// freeAddresses returns count distinct loopback addresses whose ports nothing
// listens on. It holds every port until it has them all, so the kernel can't
// hand one out twice.
func freeAddresses(ctx context.Context, count int) []string {
	GinkgoHelper()
	listeners := make([]net.Listener, 0, count)
	addresses := make([]string, 0, count)
	for range count {
		listener, err := new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		listeners = append(listeners, listener)
		addresses = append(addresses, listener.Addr().String())
	}
	for _, listener := range listeners {
		Expect(listener.Close()).To(Succeed())
	}
	return addresses
}

// newEnvironment returns an envtest environment serving the product CRDs.
// Without KUBEBUILDER_ASSETS it uses the binaries make setup-envtest installed
// for this platform under bin/k8s, so a suite also runs outside make.
func newEnvironment() (*envtest.Environment, error) {
	directory, err := utils.RepositoryPath("config", "crd", "bases")
	if err != nil {
		return nil, err
	}
	environment := &envtest.Environment{CRDDirectoryPaths: []string{directory}, ErrorIfCRDPathMissing: true}
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		assets, err := utils.RepositoryPath("bin", "k8s")
		if err != nil {
			return nil, err
		}
		environment.BinaryAssetsDirectory = binaryAssetsDirectory(assets)
	}
	// Disabling APIServerIdentity avoids the Kubernetes 1.36 shutdown deadlock
	// when the host name cannot be stored as an identity Lease label. Each API
	// server is a cluster of its own, so no spec needs peer-version
	// interoperability.
	environment.ControlPlane.GetAPIServer().Configure().Set("feature-gates", "APIServerIdentity=false,UnknownVersionInteroperabilityProxy=false")
	return environment, nil
}

// tool returns the executable the environment variable names, or else the one
// make installed for this platform as bin/<name>-<os>-<arch>.
func tool(variable, name string) (string, error) {
	if path := os.Getenv(variable); path != "" {
		return path, nil
	}
	return utils.RepositoryPath("bin", name+platformSuffix())
}

func binaryAssetsDirectory(base string) string {
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasSuffix(entry.Name(), platformSuffix()) {
			return filepath.Join(base, entry.Name())
		}
	}
	return ""
}

func platformSuffix() string {
	return "-" + runtime.GOOS + "-" + runtime.GOARCH
}
