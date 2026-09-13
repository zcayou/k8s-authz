//go:build e2e

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/zcayou/k8s-authz/internal/model"
)

const diagnosticsReader = "e2e-diagnostics-reader"

var _ = Describe("Installed snapshot diagnostics", Label("diagnostics"), func() {
	var kubeconfig, request string

	BeforeEach(func(ctx SpecContext) {
		expectBaseline(ctx)
		Expect(apply(ctx, diagnosticsReaderRBAC)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			for _, namespace := range []string{controlNamespace, operatorNamespace} {
				Expect(kubectl(ctx, "-n", namespace, "delete", "role,rolebinding", diagnosticsReader,
					"--ignore-not-found")).Error().NotTo(HaveOccurred())
			}
		})
		directory := GinkgoT().TempDir()
		kubeconfig = filepath.Join(directory, "reader.kubeconfig")
		Expect(clientcmd.WriteToFile(clientCertificateKubeconfig(ctx, diagnosticsReader), kubeconfig)).To(Succeed())
		request = filepath.Join(directory, "request.json")
		Expect(os.WriteFile(request, []byte(`{
  "apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
  "spec": {"user": "oidc:e2e-user", "groups": ["oidc:e2e-admins"],
    "resourceAttributes": {"verb": "list", "resource": "pods", "version": "v1", "namespace": "team-one"}}
}`), 0o600)).To(Succeed())
	})

	It("explains a request against the snapshot an engine has installed", func(ctx SpecContext) {
		export := filepath.Join(GinkgoT().TempDir(), "snapshot.json")
		connected, err := run(ctx, suite.cli, "explain", serviceName, "-n", controlNamespace, "--kubeconfig", kubeconfig,
			"--endpoint", endpointName, "--sar", request, "--export-snapshot", export, "--output", "json")
		Expect(err).NotTo(HaveOccurred())
		var report struct {
			Result          model.Result     `json:"result"`
			ServiceUID      model.ServiceUID `json:"serviceUID"`
			ContentRevision model.RevisionID `json:"contentRevision"`
		}
		Expect(json.Unmarshal([]byte(connected), &report)).To(Succeed())
		service := authorizationService(ctx)
		Expect(report.Result).To(Equal(model.Result("Allow")))
		Expect(report.ServiceUID).To(Equal(model.ServiceUID(service.UID)))
		Expect(report.ContentRevision).To(Equal(model.RevisionID(service.Status.DesiredRevision)))

		By("explaining the exported snapshot offline")
		offline, err := run(ctx, suite.cli, "explain", "--snapshot", export, "--endpoint", endpointName,
			"--sar", request, "--output", "json")
		Expect(err).NotTo(HaveOccurred())
		Expect(offline).To(MatchJSON(connected))
		data, err := os.ReadFile(export)
		Expect(err).NotTo(HaveOccurred())
		var exported struct {
			State model.ContentRevision `json:"state"`
		}
		Expect(json.Unmarshal(data, &exported)).To(Succeed())
		Expect(exported.State.Revision).To(Equal(report.ContentRevision))
	})

	It("refuses a service the caller may not read", func(ctx SpecContext) {
		output, err := run(ctx, suite.cli, "explain", "other", "-n", controlNamespace, "--kubeconfig", kubeconfig,
			"--pod", enginePods(ctx)[0].Name, "--endpoint", endpointName, "--sar", request)
		Expect(err).To(HaveOccurred())
		Expect(output).To(ContainSubstring("HTTP 403"))
	})
})

// clientCertificateKubeconfig returns a kubeconfig for the current cluster
// that authenticates as user with a client certificate the cluster's signer
// issued.
func clientCertificateKubeconfig(ctx context.Context, user string) clientcmdapi.Config {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: user}}, key)
	Expect(err).NotTo(HaveOccurred())
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	Expect(err).NotTo(HaveOccurred())
	Expect(apply(ctx, fmt.Sprintf(`apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: %s
spec:
  request: %s
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 3600
  usages: [client auth]
`, user, base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))))).To(Succeed())
	DeferCleanup(func(ctx SpecContext) {
		Expect(kubectl(ctx, "delete", "csr", user, "--ignore-not-found")).Error().NotTo(HaveOccurred())
	})
	Expect(kubectl(ctx, "certificate", "approve", user)).Error().NotTo(HaveOccurred())
	var certificate []byte
	Eventually(func(g Gomega) {
		var request certificatesv1.CertificateSigningRequest
		g.Expect(getJSON(ctx, &request, "csr", user)).To(Succeed())
		g.Expect(request.Status.Certificate).NotTo(BeEmpty())
		certificate = request.Status.Certificate
	}, time.Minute).Should(Succeed())

	current, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	Expect(err).NotTo(HaveOccurred())
	cluster := current.Clusters[current.Contexts[current.CurrentContext].Cluster]
	Expect(cluster).NotTo(BeNil())
	return clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{"e2e": cluster},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{user: {
			ClientCertificateData: certificate,
			ClientKeyData:         pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		}},
		Contexts:       map[string]*clientcmdapi.Context{user: {Cluster: "e2e", AuthInfo: user}},
		CurrentContext: user,
	}
}

// diagnosticsReaderRBAC grants the documented diagnostics rule for the fleet
// service, and what connected explain needs to find an engine pod
// and port-forward to the operator.
const diagnosticsReaderRBAC = `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: authz-system
  name: e2e-diagnostics-reader
rules:
  - apiGroups: [authorization.zctx.io]
    resources: [authorizationservices/diagnostics]
    resourceNames: [fleet]
    verbs: [get]
  - apiGroups: [""]
    resources: [pods]
    verbs: [list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: authz-system
  name: e2e-diagnostics-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: e2e-diagnostics-reader
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: e2e-diagnostics-reader
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: k8s-authz-system
  name: e2e-diagnostics-reader
rules:
  - apiGroups: [""]
    resources: [pods]
    verbs: [list]
  - apiGroups: [""]
    resources: [pods/portforward]
    verbs: [get, create]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: k8s-authz-system
  name: e2e-diagnostics-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: e2e-diagnostics-reader
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: e2e-diagnostics-reader
`
