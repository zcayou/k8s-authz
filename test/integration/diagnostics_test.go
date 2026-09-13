//go:build integration

package integration

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/diagnostics"
	"github.com/zcayou/k8s-authz/internal/model"
)

var _ = Describe("Diagnostics endpoint", func() {
	var (
		namespace string
		pod       *corev1.Pod
		roots     *x509.CertPool
	)
	BeforeEach(func(ctx SpecContext) {
		namespace = newNamespace(ctx, "diagnostics")
		service := createService(ctx, namespace, nil)
		installTLS(ctx, service)
		pod = createEnginePod(ctx, namespace, "engine", podAddress(6), deployment(ctx, service).Spec.Template, true)
		Eventually(func(g Gomega) model.RevisionID { return pushed(g, pod).Revision }).WithTimeout(convergence).ShouldNot(BeEmpty())
		Expect(k8sClient.Create(ctx, &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "diagnostics"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{api.GroupVersion.Group}, Resources: []string{"authorizationservices/diagnostics"}, ResourceNames: []string{service.Name}, Verbs: []string{"get"}}},
		})).To(Succeed())
		Expect(k8sClient.Create(ctx, &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "diagnostics"},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "diagnostics"},
			Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: "reader"}},
		})).To(Succeed())
		authority, err := os.ReadFile(diagnosticsCAPath)
		Expect(err).NotTo(HaveOccurred())
		roots = x509.NewCertPool()
		Expect(roots.AppendCertsFromPEM(authority)).To(BeTrue())
	})

	// request reads the pod's snapshot with certificate or bearer, and returns
	// the response status and body, or zero while the endpoint is unreachable.
	request := func(ctx SpecContext, certificate *tls.Certificate, bearer string) (int, []byte) {
		GinkgoHelper()
		config := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
		if certificate != nil {
			config.Certificates = []tls.Certificate{*certificate}
		}
		transport := &http.Transport{TLSClientConfig: config}
		defer transport.CloseIdleConnections()
		get, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+diagnosticsAddress+diagnostics.SnapshotPath(namespace, "authz", pod.Name), nil)
		Expect(err).NotTo(HaveOccurred())
		if bearer != "" {
			get.Header.Set("Authorization", "Bearer "+bearer)
		}
		response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(get)
		if err != nil {
			return 0, nil
		}
		defer func() { Expect(response.Body.Close()).To(Succeed()) }()
		body, err := io.ReadAll(response.Body)
		Expect(err).NotTo(HaveOccurred())
		return response.StatusCode, body
	}

	It("relays the installed snapshot to a client-certificate user the role allows", func(ctx SpecContext) {
		reader := clientCertificate("reader")
		var body []byte
		Eventually(func(g Gomega) {
			var code int
			code, body = request(ctx, &reader, "")
			g.Expect(code).To(Equal(http.StatusOK), string(body))
		}).WithTimeout(convergence).Should(Succeed())
		var relayed struct {
			State model.ContentRevision `json:"state"`
		}
		Expect(json.Unmarshal(body, &relayed)).To(Succeed())
		Expect(relayed.State.Revision).To(Equal(pushed(Default, pod).Revision))
	}, SpecTimeout(time.Minute))

	It("forbids a ServiceAccount the role doesn't name", func(ctx SpecContext) {
		token := serviceAccountToken(ctx, namespace, "prober")
		Eventually(func() int { code, _ := request(ctx, nil, token); return code }).WithTimeout(convergence).Should(Equal(http.StatusForbidden))
	}, SpecTimeout(time.Minute))
})

// clientCertificate returns the client certificate of a user the API server
// authenticates by name.
func clientCertificate(name string) tls.Certificate {
	GinkgoHelper()
	user, err := testEnv.AddUser(envtest.User{Name: name}, nil)
	Expect(err).NotTo(HaveOccurred())
	config := user.Config()
	certificate, err := tls.X509KeyPair(config.CertData, config.KeyData)
	Expect(err).NotTo(HaveOccurred())
	return certificate
}

// serviceAccountToken returns a token for the named ServiceAccount, created
// in namespace.
func serviceAccountToken(ctx SpecContext, namespace, name string) string {
	GinkgoHelper()
	Expect(k8sClient.Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}})).To(Succeed())
	clientset, err := kubernetes.NewForConfig(cfg)
	Expect(err).NotTo(HaveOccurred())
	token, err := clientset.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, name, &authenticationv1.TokenRequest{}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	return token.Status.Token
}
