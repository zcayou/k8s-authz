//go:build e2e

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

package e2e

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/zcayou/k8s-authz/test/utils"
)

const (
	// apiServerDirectory and memberAPIServerDirectory are the host directories
	// test/e2e/kind-config.yaml and test/e2e/kind-member-config.yaml mount into
	// their control-plane nodes at nodeAPIServerDirectory.
	apiServerDirectory       = "tmp/e2e/apiserver"
	memberAPIServerDirectory = "tmp/e2e/member-apiserver"
	memberKubeconfigFile     = "tmp/e2e/member.kubeconfig"
	nodeAPIServerDirectory   = "/etc/kubernetes/pki/k8s-authz-e2e"
	authorizationConfigFile  = "authorization-config.yaml"
)

// Identities of the cluster's own components and its administrator. They
// bypass the webhook, so the cluster keeps working through Node and RBAC
// while a spec makes the webhook fail.
var (
	clusterGroups = []string{
		"system:masters", "kubeadm:cluster-admins", "system:nodes", "system:serviceaccounts", "system:unauthenticated",
	}
	clusterUsers = []string{"system:kube-controller-manager", "system:kube-scheduler"}
)

var authorizationHashLabel = regexp.MustCompile(`(?:[{,])hash="(sha256:[0-9a-f]{64})"`)

// suite is the installation BeforeSuite made.
var suite *environment

// environment is the two Kind clusters make setup-test-e2e created,
// and the credentials this run issued for the installation. The control
// cluster runs the operator and the engines. The member cluster serves
// the remote source's policy, and its API server calls the member endpoint.
type environment struct {
	root          string
	runID         string
	cluster       string
	kind          string
	containerTool string
	artifacts     string
	cli           string
	control       apiServer
	member        apiServer
	// memberServer is the URL at which pods in the control cluster reach
	// the member's API server.
	memberServer string
	// servingAuthority issues the engines' serving certificate,
	// and callerAuthority the API servers' client certificates.
	servingAuthority utils.Material
	callerAuthority  utils.Material
	apiServerCaller  utils.Material
	memberCaller     utils.Material
	installed        bool
	failed           bool
}

// Specs run against the shared installation, so a failed one leaves it in place
// for debugging.
var _ = AfterEach(func(ctx SpecContext) {
	if CurrentSpecReport().Failed() {
		suite.failed = true
		suite.collectFailureDiagnostics(ctx)
	}
}, NodeTimeout(5*time.Minute))

// newEnvironment refuses to run unless the current kubeconfig context
// is the Kind cluster KIND_CLUSTER names and Kind runs the member cluster
// KIND_MEMBER_CLUSTER names, which it reaches only through the kubeconfig
// Kind reports for it, so no command reaches another cluster.
func newEnvironment(ctx context.Context) (*environment, error) {
	cluster := os.Getenv("KIND_CLUSTER")
	if cluster == "" {
		return nil, errors.New("KIND_CLUSTER must name the cluster make setup-test-e2e created")
	}
	member := os.Getenv("KIND_MEMBER_CLUSTER")
	if member == "" {
		return nil, errors.New("KIND_MEMBER_CLUSTER must name the member cluster make setup-test-e2e created")
	}
	current, err := kubectl(ctx, "config", "current-context")
	if err != nil {
		return nil, err
	}
	if current = strings.TrimSpace(current); current != "kind-"+cluster {
		return nil, fmt.Errorf("the current kubeconfig context is %q, not the Kind cluster %q", current, cluster)
	}
	root, err := utils.RepositoryPath()
	if err != nil {
		return nil, err
	}
	kind := cmp.Or(os.Getenv("KIND"), "kind")
	clusters, err := run(ctx, kind, "get", "clusters")
	if err != nil {
		return nil, err
	}
	if !slices.Contains(strings.Fields(clusters), member) {
		return nil, fmt.Errorf("Kind runs no member cluster %q", member)
	}
	external, err := kindKubeconfig(ctx, kind, member)
	if err != nil {
		return nil, err
	}
	memberKubeconfig := filepath.Join(root, memberKubeconfigFile)
	if err = os.WriteFile(memberKubeconfig, external, 0o600); err != nil {
		return nil, err
	}
	internal, err := kindKubeconfig(ctx, kind, member, "--internal")
	if err != nil {
		return nil, err
	}
	memberServer, err := currentServer(internal)
	if err != nil {
		return nil, err
	}
	runID := time.Now().UTC().Format("20060102-150405")
	return &environment{
		root:          root,
		runID:         runID,
		cluster:       cluster,
		kind:          kind,
		containerTool: cmp.Or(os.Getenv("CONTAINER_TOOL"), "docker"),
		artifacts:     filepath.Join(root, "artifacts", "e2e-"+runID),
		cli:           filepath.Join(root, "bin", "k8s-authz"),
		control:       apiServer{directory: filepath.Join(root, apiServerDirectory)},
		member:        apiServer{directory: filepath.Join(root, memberAPIServerDirectory), kubeconfig: memberKubeconfig},
		memberServer:  memberServer,
	}, nil
}

// kindKubeconfig returns the kubeconfig Kind reports for cluster.
func kindKubeconfig(ctx context.Context, kind, cluster string, flags ...string) ([]byte, error) {
	output, err := exec.CommandContext(ctx, kind, append([]string{"get", "kubeconfig", "--name", cluster}, flags...)...).Output()
	if err != nil {
		return nil, fmt.Errorf("get the kubeconfig of Kind cluster %s: %w", cluster, err)
	}
	return output, nil
}

// currentServer returns the API server URL of kubeconfig's current context.
func currentServer(kubeconfig []byte) (string, error) {
	config, err := clientcmd.Load(kubeconfig)
	if err != nil {
		return "", fmt.Errorf("decode kubeconfig: %w", err)
	}
	current, found := config.Contexts[config.CurrentContext]
	if !found {
		return "", fmt.Errorf("kubeconfig has no current context %q", config.CurrentContext)
	}
	cluster, found := config.Clusters[current.Cluster]
	if !found {
		return "", fmt.Errorf("kubeconfig has no cluster %q", current.Cluster)
	}
	return cluster.Server, nil
}

// install builds and deploys the operator from config/, installs the baseline
// documents, and puts the endpoint's webhook ahead of Node and RBAC.
func (e *environment) install(ctx context.Context) {
	GinkgoHelper()
	By("building the manager image and loading it into Kind")
	image := "k8s-authz:e2e-" + e.runID
	Expect(run(ctx, "make", "docker-build", "IMG="+image)).Error().NotTo(HaveOccurred())
	Expect(run(ctx, e.kind, "load", "docker-image", image, "--name", e.cluster)).Error().NotTo(HaveOccurred())
	Expect(run(ctx, "make", "build")).Error().NotTo(HaveOccurred())

	By("creating the Secrets config/default mounts")
	e.issueCredentials()
	Expect(e.createOperatorSecrets(ctx)).To(Succeed())

	By("installing the CRDs and the remote source's policy in the member cluster")
	Expect(e.member.make(ctx, "install")).To(Succeed())
	Expect(e.member.apply(ctx, memberNamespaces+remoteReader+remoteDocuments)).To(Succeed())

	By("installing the CRDs and deploying the operator")
	Expect(run(ctx, "make", "install")).Error().NotTo(HaveOccurred())
	Expect(run(ctx, "make", "deploy", "IMG="+image)).Error().NotTo(HaveOccurred())
	Expect(kubectl(ctx, "-n", operatorNamespace, "rollout", "status", "deployment/"+operatorDeployment,
		"--timeout=3m")).Error().NotTo(HaveOccurred())

	By("installing the policy documents and the fleet service")
	e.installBaseline(ctx)

	By("putting each endpoint's rendered webhook ahead of its API server's Node and RBAC authorizers")
	e.enableWebhooks(ctx)
	expectBaseline(ctx)
}

// uninstall removes everything install adds from both clusters and returns
// their API servers to the Node and RBAC chain, so reused clusters start from
// the state make setup-test-e2e left.
func (e *environment) uninstall(ctx context.Context) {
	GinkgoHelper()
	initial, err := os.ReadFile(filepath.Join(e.root, "test", "e2e", authorizationConfigFile))
	Expect(err).NotTo(HaveOccurred())
	e.control.installAuthorizationConfiguration(ctx, initial)
	e.member.installAuthorizationConfiguration(ctx, initial)
	Expect(e.member.kubectl(ctx, "delete", "namespace", "--ignore-not-found",
		remotePolicyNamespace, workloadNamespace)).Error().NotTo(HaveOccurred())
	Expect(e.member.kubectl(ctx, "delete", "clusterrole,clusterrolebinding", "--ignore-not-found",
		remoteReaderName)).Error().NotTo(HaveOccurred())
	Expect(e.member.make(ctx, "uninstall", "ignore-not-found=true")).To(Succeed())
	Expect(kubectl(ctx, "delete", "namespace", "--ignore-not-found",
		controlNamespace, localPolicyNamespace, workloadNamespace)).Error().NotTo(HaveOccurred())
	Expect(run(ctx, "make", "undeploy", "ignore-not-found=true")).Error().NotTo(HaveOccurred())
	Expect(run(ctx, "make", "uninstall", "ignore-not-found=true")).Error().NotTo(HaveOccurred())
}

func (e *environment) issueCredentials() {
	GinkgoHelper()
	var err error
	now := time.Now()
	e.servingAuthority, err = utils.NewAuthority(now)
	Expect(err).NotTo(HaveOccurred())
	e.callerAuthority, err = utils.NewAuthority(now)
	Expect(err).NotTo(HaveOccurred())
	e.apiServerCaller, err = e.callerAuthority.Issue("k8s-authz-e2e-apiserver", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	Expect(err).NotTo(HaveOccurred())
	e.memberCaller, err = e.callerAuthority.Issue("k8s-authz-e2e-member-apiserver", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	Expect(err).NotTo(HaveOccurred())
}

// createOperatorSecrets creates the management and diagnostics Secrets.
// The diagnostics endpoint is reached through a port-forward, so its
// certificate needs no names.
func (e *environment) createOperatorSecrets(ctx context.Context) error {
	management, err := utils.NewAuthority(time.Now())
	if err != nil {
		return err
	}
	client, err := management.Issue("k8s-authz-e2e-management", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err != nil {
		return err
	}
	diagnostics, err := management.Issue("k8s-authz-e2e-diagnostics", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err != nil {
		return err
	}
	if err = apply(ctx, "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: "+operatorNamespace+"\n"); err != nil {
		return err
	}
	for _, secret := range []corev1.Secret{
		tlsSecret("management-client-cert", client),
		{ObjectMeta: metav1.ObjectMeta{Name: "management-ca"}, Data: map[string][]byte{caKey: management.CertificatePEM}},
		tlsSecret("diagnostics-server-cert", diagnostics),
	} {
		secret.Namespace = operatorNamespace
		if err = applySecret(ctx, secret); err != nil {
			return err
		}
	}
	return nil
}

// enableWebhooks has each cluster's API server call its endpoint: the control
// cluster's through the listener's ClusterIP, and the member's through
// the listener's NodePort on the control cluster's control-plane node.
func (e *environment) enableWebhooks(ctx context.Context) {
	GinkgoHelper()
	e.enableWebhook(ctx, e.control, endpointName, e.apiServerCaller, net.JoinHostPort(listenerClusterIP, "443"))
	node, err := kubectl(ctx, "get", "node", e.cluster+"-control-plane",
		"-o", `jsonpath={.status.addresses[?(@.type=="InternalIP")].address}`)
	Expect(err).NotTo(HaveOccurred())
	Expect(node).NotTo(BeEmpty())
	e.enableWebhook(ctx, e.member, memberEndpointName, e.memberCaller, net.JoinHostPort(node, strconv.Itoa(listenerNodePort)))
}

// enableWebhook writes caller's identity and the serving CA beside the webhook
// configuration render-caller-config writes for endpoint, reached at address,
// and waits for target to load it.
func (e *environment) enableWebhook(ctx context.Context, target apiServer, endpoint string, caller utils.Material, address string) {
	GinkgoHelper()
	for name, data := range map[string][]byte{
		"client.crt":    caller.CertificatePEM,
		"client.key":    caller.KeyPEM,
		"server-ca.crt": e.servingAuthority.CertificatePEM,
	} {
		Expect(os.WriteFile(filepath.Join(target.directory, name), data, 0o600)).To(Succeed())
	}
	recovery := make([]string, 0, 2*(len(clusterGroups)+len(clusterUsers)))
	for _, group := range clusterGroups {
		recovery = append(recovery, "--recovery-group", group)
	}
	for _, user := range clusterUsers {
		recovery = append(recovery, "--recovery-user", user)
	}
	args := append([]string{"render-caller-config", serviceName, "-n", controlNamespace, "--endpoint", endpoint,
		"--webhook-server", "https://" + address,
		"--caller-certificate", path.Join(nodeAPIServerDirectory, "client.crt"),
		"--caller-key", path.Join(nodeAPIServerDirectory, "client.key"),
		"--engine-ca", path.Join(nodeAPIServerDirectory, "server-ca.crt"),
		"--webhook-kubeconfig-path", path.Join(nodeAPIServerDirectory, "webhook.kubeconfig"),
		"--authorized-ttl=0", "--unauthorized-ttl=0", "--output-dir", target.directory}, recovery...)
	Expect(run(ctx, e.cli, args...)).Error().NotTo(HaveOccurred())
	rendered, err := os.ReadFile(filepath.Join(target.directory, authorizationConfigFile))
	Expect(err).NotTo(HaveOccurred())
	target.waitForAuthorizationConfiguration(ctx, rendered)
}

// installAuthorizationConfiguration replaces the API server's authorization
// configuration and waits for it to load it.
func (a apiServer) installAuthorizationConfiguration(ctx context.Context, data []byte) {
	GinkgoHelper()
	target := filepath.Join(a.directory, authorizationConfigFile)
	temporary := target + ".tmp"
	Expect(os.WriteFile(temporary, data, 0o644)).To(Succeed())
	Expect(os.Rename(temporary, target)).To(Succeed())
	a.waitForAuthorizationConfiguration(ctx, data)
}

// waitForAuthorizationConfiguration waits for the API server to report data
// as its loaded authorization configuration. It rereads the file about once
// a minute.
func (a apiServer) waitForAuthorizationConfiguration(ctx context.Context, data []byte) {
	GinkgoHelper()
	digest := sha256.Sum256(data)
	expected := "sha256:" + hex.EncodeToString(digest[:])
	Eventually(func(g Gomega) {
		metrics, err := a.kubectl(ctx, "get", "--raw=/metrics")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(authorizationConfigurationHashes(metrics)).To(ContainElement(expected))
	}, 3*time.Minute).Should(Succeed())
}

func authorizationConfigurationHashes(metrics string) []string {
	const metric = "apiserver_authorization_config_controller_last_config_info"
	var hashes []string
	for line := range strings.Lines(metrics) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, metric+"{") || !strings.HasSuffix(line, " 1") {
			continue
		}
		if match := authorizationHashLabel.FindStringSubmatch(line); len(match) == 2 {
			hashes = append(hashes, match[1])
		}
	}
	return hashes
}

// collectFailureDiagnostics keeps both clusters' state for the current spec
// under artifacts/e2e-<run>/, the member's in its member/ subdirectory.
func (e *environment) collectFailureDiagnostics(ctx context.Context) {
	spec := strings.Trim(artifactName.ReplaceAllString(strings.ToLower(CurrentSpecReport().FullText()), "-"), "-")
	directory := filepath.Join(e.artifacts, spec)
	recordState(ctx, e.control, directory, map[string][]string{
		"resources.log": {"get", "pods,deployments,daemonsets,services,configmaps,poddisruptionbudgets," +
			"authorizationservices,policysources", "--all-namespaces", "-o", "wide"},
		"operator.log": {"-n", operatorNamespace, "logs", "deployment/" + operatorDeployment, "--all-containers"},
	})
	recordState(ctx, e.member, filepath.Join(directory, "member"), map[string][]string{
		"resources.log": {"get", "policies,policybindings,policysets,roles,rolebindings", "--all-namespaces", "-o", "wide"},
	})
}

// recordState writes into directory what each of commands outputs against
// target, with its Events and a cluster-info dump.
func recordState(ctx context.Context, target apiServer, directory string, commands map[string][]string) {
	if err := os.MkdirAll(directory, 0o750); err != nil {
		_, _ = fmt.Fprintln(GinkgoWriter, err)
		return
	}
	commands["events.log"] = []string{"get", "events", "--all-namespaces", "--sort-by=.lastTimestamp"}
	commands["cluster-dump.log"] = []string{"cluster-info", "dump", "--all-namespaces",
		"--output-directory", filepath.Join(directory, "cluster-dump")}
	for name, args := range commands {
		output, err := target.kubectl(ctx, append([]string{"--request-timeout=20s"}, args...)...)
		if err != nil {
			output += "\n" + err.Error()
		}
		if err = os.WriteFile(filepath.Join(directory, name), []byte(output), 0o600); err != nil {
			_, _ = fmt.Fprintln(GinkgoWriter, err)
		}
	}
}
