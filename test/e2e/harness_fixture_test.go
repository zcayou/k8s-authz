//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/resources"
	"github.com/zcayou/k8s-authz/test/utils"
)

const (
	operatorNamespace     = "k8s-authz-system"
	operatorDeployment    = "k8s-authz-controller-manager"
	controlNamespace      = "authz-system"
	localPolicyNamespace  = "e2e-local"
	remotePolicyNamespace = "e2e-remote"
	workloadNamespace     = "team-one"
	remoteReaderName      = "remote-reader"
	serviceName           = "fleet"
	listenerName          = "authz-fleet"
	listenerClusterIP     = "10.96.0.11"
	listenerNodePort      = 30443
	endpointName          = "cluster"
	memberEndpointName    = "member"
	caKey                 = "ca.crt"
	e2eUser               = "oidc:e2e-user"
	e2eAdminGroup         = "oidc:e2e-admins"
)

var (
	forwardingAddress = regexp.MustCompile(`Forwarding from 127\.0\.0\.1:([0-9]+) ->`)
	artifactName      = regexp.MustCompile(`[^a-z0-9]+`)
)

// run executes a command from the repository root and returns its combined
// output, which errors also carry.
func run(ctx context.Context, name string, args ...string) (string, error) {
	return runCommand(exec.CommandContext(ctx, name, args...))
}

func runCommand(command *exec.Cmd) (string, error) {
	root, err := utils.RepositoryPath()
	if err != nil {
		return "", err
	}
	command.Dir = root
	if command.Env == nil {
		command.Env = os.Environ()
	}
	command.Env = append(command.Env, "KUBECTL_KUBERC=false")
	line := strings.Join(command.Args, " ")
	_, _ = fmt.Fprintf(GinkgoWriter, "running: %s\n", line)
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("run %s: %s: %w", line, strings.TrimSpace(string(output)), err)
	}
	return string(output), nil
}

func kubectl(ctx context.Context, args ...string) (string, error) {
	return run(ctx, "kubectl", args...)
}

// apply server-side applies manifest.
func apply(ctx context.Context, manifest string) error {
	return applyWith(ctx, manifest)
}

// applyWith server-side applies manifest with the kubectl flags flags.
func applyWith(ctx context.Context, manifest string, flags ...string) error {
	command := exec.CommandContext(ctx, "kubectl", append(flags, "apply", "--server-side", "--field-manager=k8s-authz-e2e", "-f", "-")...)
	command.Stdin = strings.NewReader(manifest)
	_, err := runCommand(command)
	return err
}

// apiServer is one of the suite's Kind API servers, which reads its
// authorization configuration from directory on the host. kubeconfig reaches
// it, or is empty for the current context.
type apiServer struct {
	directory  string
	kubeconfig string
}

func (a apiServer) flags() []string {
	if a.kubeconfig == "" {
		return nil
	}
	return []string{"--kubeconfig", a.kubeconfig}
}

func (a apiServer) kubectl(ctx context.Context, args ...string) (string, error) {
	return kubectl(ctx, slices.Concat(a.flags(), args)...)
}

func (a apiServer) apply(ctx context.Context, manifest string) error {
	return applyWith(ctx, manifest, a.flags()...)
}

func (a apiServer) getJSON(ctx context.Context, object any, args ...string) error {
	return getJSON(ctx, object, slices.Concat(a.flags(), args)...)
}

// make runs the make targets against the API server.
func (a apiServer) make(ctx context.Context, targets ...string) error {
	command := exec.CommandContext(ctx, "make", targets...)
	if a.kubeconfig != "" {
		command.Env = append(os.Environ(), "KUBECONFIG="+a.kubeconfig)
	}
	_, err := runCommand(command)
	return err
}

func applySecret(ctx context.Context, secret corev1.Secret) error {
	secret.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}
	data, err := json.Marshal(secret)
	if err != nil {
		return fmt.Errorf("encode Secret %s: %w", secret.Name, err)
	}
	return apply(ctx, string(data))
}

func tlsSecret(name string, certificate utils.Material) corev1.Secret {
	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{corev1.TLSCertKey: certificate.CertificatePEM, corev1.TLSPrivateKeyKey: certificate.KeyPEM},
	}
}

// getJSON decodes the object kubectl get returns for args into object.
func getJSON(ctx context.Context, object any, args ...string) error {
	output, err := kubectl(ctx, append(append([]string{"get"}, args...), "-o", "json")...)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(output), object)
}

// patchService merge-patches the fleet AuthorizationService.
func patchService(ctx context.Context, patch string) error {
	_, err := kubectl(ctx, "-n", controlNamespace, "patch", "authorizationservice", serviceName, "--type=merge", "-p", patch)
	return err
}

func authorizationService(ctx context.Context) api.AuthorizationService {
	GinkgoHelper()
	var service api.AuthorizationService
	Expect(getJSON(ctx, &service, "-n", controlNamespace, "authorizationservice", serviceName)).To(Succeed())
	return service
}

// expectConverged waits until every engine the fleet workload expects serves
// the desired revision of the service's current generation.
func expectConverged(ctx context.Context, timeout time.Duration) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		service := authorizationService(ctx)
		status := service.Status
		g.Expect(status.ObservedGeneration).To(Equal(service.Generation))
		g.Expect(apimeta.IsStatusConditionTrue(status.Conditions, api.ConditionPrepared)).To(BeTrue())
		g.Expect(apimeta.IsStatusConditionTrue(status.Conditions, api.ConditionReady)).To(BeTrue())
		g.Expect(status.DesiredRevision).NotTo(BeEmpty())
		g.Expect(status.DesiredReplicas).To(HaveValue(Equal(int32(2))))
		g.Expect(status.ReadyReplicas).To(Equal(int32(2)))
		g.Expect(status.CurrentReplicas).To(Equal(int32(2)))
	}, timeout).Should(Succeed())
}

// expectBaseline waits for the state every spec starts from: the operator
// available and the fleet service converged on two Deployment engines.
func expectBaseline(ctx context.Context) {
	GinkgoHelper()
	Expect(kubectl(ctx, "-n", operatorNamespace, "rollout", "status", "deployment/"+operatorDeployment,
		"--timeout=3m")).Error().NotTo(HaveOccurred())
	Expect(authorizationService(ctx).Spec.Runtime.Type).To(Equal(api.RuntimeTypeDeployment))
	expectConverged(ctx, 3*time.Minute)
}

// expectRolledOut waits until the fleet Deployment has replaced every pod
// with one from its current template.
func expectRolledOut(ctx context.Context) {
	GinkgoHelper()
	Expect(kubectl(ctx, "-n", controlNamespace, "rollout", "status", "deployment/"+listenerName,
		"--timeout=3m")).Error().NotTo(HaveOccurred())
}

// enginePods returns the fleet service's ready engine pods, by name.
func enginePods(ctx context.Context) []corev1.Pod {
	GinkgoHelper()
	var pods corev1.PodList
	Expect(getJSON(ctx, &pods, "-n", controlNamespace, "pods",
		"-l", resources.LabelServiceUID+"="+string(authorizationService(ctx).UID))).To(Succeed())
	ready := slices.DeleteFunc(pods.Items, func(pod corev1.Pod) bool { return !resources.PodReady(&pod) })
	slices.SortFunc(ready, func(a, b corev1.Pod) int { return strings.Compare(a.Name, b.Name) })
	return ready
}

func podUIDs(pods []corev1.Pod) []string {
	uids := make([]string, 0, len(pods))
	for _, pod := range pods {
		uids = append(uids, string(pod.UID))
	}
	return uids
}

// startupDigest returns the startup digest of the fleet workload's pod
// template.
func startupDigest(ctx context.Context) string {
	GinkgoHelper()
	kind := "deployment"
	if authorizationService(ctx).Spec.Runtime.Type == api.RuntimeTypeDaemonSet {
		kind = "daemonset"
	}
	var template struct {
		Spec struct {
			Template corev1.PodTemplateSpec `json:"template"`
		} `json:"spec"`
	}
	Expect(getJSON(ctx, &template, "-n", controlNamespace, kind, listenerName)).To(Succeed())
	digest := template.Spec.Template.Annotations[resources.AnnotationStartupDigest]
	Expect(digest).NotTo(BeEmpty())
	return digest
}

// listPods lists pods in workloadNamespace as an oidc: user in group, through
// the API server's authorizer chain.
func listPods(ctx context.Context, user, group string) (string, error) {
	return kubectl(ctx, "get", "pods", "-n", workloadNamespace, "--as="+user, "--as-group="+group)
}

// review sends endpoint on pod a SubjectAccessReview, presenting caller's
// certificate, and returns the response status. Each review has a port-forward
// of its own, because kubectl ends a port-forward whose connection the engine
// resets, as it does when it refuses a client certificate.
func review(ctx context.Context, pod, endpoint string, caller utils.Material) (int, error) {
	session, address, err := startPortForward(ctx, controlNamespace, "pod/"+pod, int(resources.EnginePort))
	if err != nil {
		return 0, err
	}
	defer func() { session.Terminate().Wait(10 * time.Second) }()
	roots := x509.NewCertPool()
	roots.AddCert(suite.servingAuthority.Certificate)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: listenerName + "." + controlNamespace + ".svc", Certificates: []tls.Certificate{caller.TLS},
	}}}
	body := `{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"` + e2eUser + `","groups":["` + e2eAdminGroup + `"],` +
		`"resourceAttributes":{"verb":"list","resource":"pods","version":"v1","namespace":"` + workloadNamespace + `"}}}`
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+address+"/v0/data/authz/endpoints/"+endpoint+"/decision", strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	return response.StatusCode, response.Body.Close()
}

// expectMemberPodList waits until the member's API server lets the e2e admin
// list pods in namespace when allowed, or refuses it with the webhook's
// fallback otherwise.
func expectMemberPodList(ctx context.Context, namespace string, allowed bool) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		output, err := suite.member.kubectl(ctx, "get", "pods", "-n", namespace,
			"--as="+e2eUser, "--as-group="+e2eAdminGroup)
		if allowed {
			g.Expect(err).NotTo(HaveOccurred())
			return
		}
		g.Expect(err).To(HaveOccurred())
		g.Expect(output).To(ContainSubstring("Forbidden"))
		g.Expect(output).To(ContainSubstring("code=AuthorityFallback"))
	}, 2*time.Minute).Should(Succeed())
}

// expectAllowed waits until the API server lets the e2e admin list pods.
func expectAllowed(ctx context.Context, timeout time.Duration) {
	GinkgoHelper()
	Eventually(func() error {
		_, err := listPods(ctx, e2eUser, e2eAdminGroup)
		return err
	}, timeout).Should(Succeed())
}

// expectForbidden waits until the API server refuses the e2e admin's pod list.
func expectForbidden(ctx context.Context, timeout time.Duration) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		output, err := listPods(ctx, e2eUser, e2eAdminGroup)
		g.Expect(err).To(HaveOccurred())
		g.Expect(output).To(ContainSubstring("Forbidden"))
	}, timeout).Should(Succeed())
}

// portForward forwards a local port to port on target for the rest of the spec,
// and returns the local address.
func portForward(ctx context.Context, namespace, target string, port int) string {
	GinkgoHelper()
	session, address, err := startPortForward(ctx, namespace, target, port)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { session.Terminate().Wait(10 * time.Second) })
	return address
}

// startPortForward forwards a local port to port on target until the returned
// session is terminated, and returns the local address.
func startPortForward(ctx context.Context, namespace, target string, port int) (*gexec.Session, string, error) {
	command := exec.CommandContext(ctx, "kubectl", "-n", namespace, "port-forward", "--address=127.0.0.1",
		target, ":"+strconv.Itoa(port))
	command.Env = append(os.Environ(), "KUBECTL_KUBERC=false")
	session, err := gexec.Start(command, GinkgoWriter, GinkgoWriter)
	if err != nil {
		return nil, "", err
	}
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline) && session.ExitCode() == -1; time.Sleep(100 * time.Millisecond) {
		if match := forwardingAddress.FindSubmatch(session.Out.Contents()); match != nil {
			return session, "127.0.0.1:" + string(match[1]), nil
		}
	}
	session.Terminate().Wait(10 * time.Second)
	return nil, "", fmt.Errorf("port-forward to %s did not start: %s", target, session.Err.Contents())
}

// restartOPA stops the pod's OPA container, which the kubelet then restarts
// in the same pod.
func restartOPA(ctx context.Context, pod corev1.Pod) {
	GinkgoHelper()
	Expect(pod.Status.ContainerStatuses).To(HaveLen(1))
	id := strings.TrimPrefix(pod.Status.ContainerStatuses[0].ContainerID, "containerd://")
	Expect(id).NotTo(BeEmpty())
	Expect(run(ctx, suite.containerTool, "exec", pod.Spec.NodeName, "crictl", "stop", id)).Error().NotTo(HaveOccurred())
}
