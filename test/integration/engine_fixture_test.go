//go:build integration

package integration

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/engineclient"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/resources"
	"github.com/zcayou/k8s-authz/test/utils"
)

const (
	managementIdentity = "k8s-authz-operator"
	decisionTarget     = "/v0/data/authz/endpoints/cluster/decision"
)

// engineFixture is one stock OPA process started from the engine ConfigMap
// resources.Build renders, with the production argument vector on loopback
// addresses.
type engineFixture struct {
	service      model.ServiceUID
	address      string
	diagnostic   string
	serverName   string
	servingRoots *x509.CertPool
	// clientCA issues the webhook callers' certificates, and managementCA
	// the operator's.
	clientCA, managementCA utils.Material
	management             *engineclient.Client
	target                 engineclient.Target
	session                *gexec.Session
	// command is the engine's command line, to restart it with.
	command []string
}

func startEngineFixture(ctx SpecContext, logs bool) *engineFixture {
	GinkgoHelper()
	binary, err := tool("OPA_BINARY", "opa")
	Expect(err).NotTo(HaveOccurred())
	version, err := exec.CommandContext(ctx, binary, "version").CombinedOutput()
	Expect(err).NotTo(HaveOccurred())
	Expect(string(version)).To(ContainSubstring("Version: " + engine.RuntimeVersion + "\n"))

	service := utils.AuthorizationService(types.NamespacedName{Namespace: "control", Name: "authz"})
	serverName := resources.ServerName(service.Namespace, service.Name)
	servingCA, clientCA, managementCA := authority(), authority(), authority()
	server, err := servingCA.Issue("server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, serverName)
	Expect(err).NotTo(HaveOccurred())
	operator, err := managementCA.Issue(managementIdentity, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	Expect(err).NotTo(HaveOccurred())
	bootstrap, err := engine.NewBootstrap(model.ServiceUID(service.UID), managementCA.CertificatePEM, managementIdentity)
	Expect(err).NotTo(HaveOccurred())
	runtime, err := resources.Build(resources.BuildInput{
		Service: service, EngineImage: engineImage, DecisionLogs: logs, Bootstrap: bootstrap,
		CABundle: slices.Concat(managementCA.CertificatePEM, clientCA.CertificatePEM),
	})
	Expect(err).NotTo(HaveOccurred())

	addresses := freeAddresses(ctx, 2)
	layout := resources.Layout{
		Address:           addresses[0],
		DiagnosticAddress: "http://" + addresses[1],
		EngineDirectory:   GinkgoT().TempDir(),
		TLSDirectory:      GinkgoT().TempDir(),
	}
	for key, value := range runtime.ConfigMap.Data {
		writeFile(filepath.Join(layout.EngineDirectory, resources.ItemPath(key)), []byte(value))
	}
	writeFile(filepath.Join(layout.TLSDirectory, corev1.TLSCertKey), server.CertificatePEM)
	writeFile(filepath.Join(layout.TLSDirectory, corev1.TLSPrivateKeyKey), server.KeyPEM)

	servingRoots := x509.NewCertPool()
	servingRoots.AddCert(servingCA.Certificate)
	fixture := &engineFixture{
		service: bootstrap.ServiceUID, address: layout.Address, diagnostic: layout.DiagnosticAddress,
		serverName: serverName, servingRoots: servingRoots,
		clientCA: clientCA, managementCA: managementCA,
		management: managementClient(operator),
		target:     engineclient.Target{Address: layout.Address, ServerName: serverName, Roots: servingRoots},
		command:    append([]string{binary}, append(layout.Arguments(), "--log-level=error")...),
	}
	fixture.start()
	DeferCleanup(fixture.stop)
	return fixture
}

func (f *engineFixture) start() {
	GinkgoHelper()
	session, err := gexec.Start(exec.Command(f.command[0], f.command[1:]...), GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	f.session = session
	Eventually(func() int { return f.probe("/health/live") }, 10*time.Second).Should(Equal(http.StatusOK))
}

func (f *engineFixture) stop() {
	GinkgoHelper()
	f.session.Interrupt()
	Eventually(f.session, 20*time.Second).Should(gexec.Exit(0))
}

// restart stops the engine and starts it again from its files.
func (f *engineFixture) restart() {
	GinkgoHelper()
	f.stop()
	f.start()
}

// install pushes prepared, compiled for the fixture's evaluator,
// as the operator does: its conditions module, then its state.
func (f *engineFixture) install(ctx SpecContext, prepared model.PreparedRevision) model.ContentRevision {
	GinkgoHelper()
	content, module, err := engine.FinalizeContent(prepared, f.service)
	Expect(err).NotTo(HaveOccurred())
	Expect(f.management.PutConditions(ctx, f.target, module)).To(Succeed())
	state, err := json.Marshal(content)
	Expect(err).NotTo(HaveOccurred())
	Expect(f.management.Replace(ctx, f.target, state)).To(Succeed())
	Expect(f.management.Installed(ctx, f.target)).To(Equal(engineclient.Installed{Revision: content.Revision, ConditionsDigest: module.Digest}))
	return content
}

// installed returns the state the engine serves, as the operator reads it.
func (f *engineFixture) installed(ctx SpecContext) model.ContentRevision {
	GinkgoHelper()
	state, err := f.management.Snapshot(ctx, f.target)
	Expect(err).NotTo(HaveOccurred())
	var content model.ContentRevision
	Expect(json.Unmarshal(state, &content)).To(Succeed())
	return content
}

func (f *engineFixture) probe(path string) int {
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Get(f.diagnostic + path)
	if err != nil {
		return 0
	}
	if err = response.Body.Close(); err != nil {
		return 0
	}
	return response.StatusCode
}

// client returns an HTTP client that verifies the engine's serving certificate
// and presents certificate.
func (f *engineFixture) client(certificate utils.Material) *http.Client {
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: f.servingRoots, ServerName: f.serverName, Certificates: []tls.Certificate{certificate.TLS},
	}}}
}

// caller returns a client certificate the service's client CA issued
// for commonName.
func (f *engineFixture) caller(commonName string) utils.Material {
	GinkgoHelper()
	certificate, err := f.clientCA.Issue(commonName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	Expect(err).NotTo(HaveOccurred())
	return certificate
}

// output returns everything the engine has written.
func (f *engineFixture) output() []byte {
	return slices.Concat(f.session.Out.Contents(), f.session.Err.Contents())
}

func (f *engineFixture) review(ctx SpecContext, client *http.Client, review authorizationv1.SubjectAccessReview) *http.Response {
	GinkgoHelper()
	data, err := json.Marshal(review)
	Expect(err).NotTo(HaveOccurred())
	return f.do(ctx, client, http.MethodPost, decisionTarget, data)
}

func (f *engineFixture) do(ctx SpecContext, client *http.Client, method, path string, body []byte) *http.Response {
	GinkgoHelper()
	request, err := http.NewRequestWithContext(ctx, method, "https://"+f.address+path, bytes.NewReader(body))
	Expect(err).NotTo(HaveOccurred())
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("%s %s", method, path))
	return response
}

func decode(response *http.Response) authorizationv1.SubjectAccessReview {
	GinkgoHelper()
	Expect(response.StatusCode).To(Equal(http.StatusOK))
	var decision authorizationv1.SubjectAccessReview
	Expect(json.NewDecoder(response.Body).Decode(&decision)).To(Succeed())
	Expect(response.Body.Close()).To(Succeed())
	return decision
}

func secretProhibitionProgram() model.PreparedRevision {
	GinkgoHelper()
	program, err := utils.SecretProhibitionProgram()
	Expect(err).NotTo(HaveOccurred())
	return program
}

func writeFile(path string, data []byte) {
	GinkgoHelper()
	Expect(os.MkdirAll(filepath.Dir(path), 0o700)).To(Succeed())
	Expect(os.WriteFile(path, data, 0o600)).To(Succeed())
}

func managementClient(certificate utils.Material) *engineclient.Client {
	return engineclient.New(func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &certificate.TLS, nil })
}
