package engineclient_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/engineclient"
	"github.com/zcayou/k8s-authz/test/utils"
)

const (
	testServerName = "authz-service.control.svc"
	installedPath  = "GET /v1/data/authz/evaluator/installed"
)

// engineServer stands in for an engine's management API.
type engineServer struct {
	mutex     sync.Mutex
	status    int
	responses map[string]string
	requests  []*http.Request
	bodies    [][]byte
	callers   []string
}

func (s *engineServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	defer GinkgoRecover()
	body, err := io.ReadAll(request.Body)
	Expect(err).NotTo(HaveOccurred())
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.requests = append(s.requests, request)
	s.bodies = append(s.bodies, body)
	s.callers = append(s.callers, request.TLS.PeerCertificates[0].Subject.CommonName)
	if s.status != 0 {
		writer.WriteHeader(s.status)
		return
	}
	response, found := s.responses[request.Method+" "+request.URL.Path]
	if !found {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	_, err = io.WriteString(writer, response)
	Expect(err).NotTo(HaveOccurred())
}

var _ = Describe("Engine management client", func() {
	var server *engineServer
	var client *engineclient.Client
	var target engineclient.Target
	var certificate atomic.Pointer[tls.Certificate]
	var authority utils.Material
	BeforeEach(func() {
		var err error
		authority, err = utils.NewAuthority(time.Now())
		Expect(err).NotTo(HaveOccurred())
		serving, err := authority.Issue("engine", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, testServerName)
		Expect(err).NotTo(HaveOccurred())
		operator, err := authority.Issue("operator", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		Expect(err).NotTo(HaveOccurred())
		certificate.Store(&operator.TLS)
		server = &engineServer{responses: map[string]string{}}
		listener := httptest.NewUnstartedServer(server)
		roots := x509.NewCertPool()
		roots.AddCert(authority.Certificate)
		listener.Config.ErrorLog = log.New(GinkgoWriter, "", 0)
		listener.TLS = &tls.Config{Certificates: []tls.Certificate{serving.TLS}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
		listener.StartTLS()
		DeferCleanup(listener.Close)
		target = engineclient.Target{Address: strings.TrimPrefix(listener.URL, "https://"), ServerName: testServerName, Roots: roots}
		client = engineclient.New(func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return certificate.Load(), nil })
	})

	It("reads the installed revision and conditions digest, or none", func(ctx SpecContext) {
		server.responses[installedPath] = `{}`
		Expect(client.Installed(ctx, target)).To(BeZero())
		server.responses[installedPath] = `{"result":{"revision":"","conditions_digest":""}}`
		Expect(client.Installed(ctx, target)).To(BeZero())
		server.responses[installedPath] = `{"result":{"revision":"sha256:1","conditions_digest":"sha256:2"}}`
		Expect(client.Installed(ctx, target)).To(Equal(engineclient.Installed{Revision: "sha256:1", ConditionsDigest: "sha256:2"}))
	})

	It("replaces the conditions module under its policy ID", func(ctx SpecContext) {
		server.responses["PUT /v1/policies/k8s-authz/conditions"] = `{}`
		module := condition.Module{Source: []byte("package authz.conditions\n"), Digest: "sha256:1"}
		Expect(client.PutConditions(ctx, target, module)).To(Succeed())
		Expect(server.requests).To(HaveLen(1))
		Expect(server.bodies[0]).To(Equal(module.Source))
	})

	It("replaces the state with the encoded document", func(ctx SpecContext) {
		server.responses["PUT /v1/data/authz/state"] = ""
		state := []byte(`{"revision":"sha256:1"}`)
		Expect(client.Replace(ctx, target, state)).To(Succeed())
		Expect(server.requests).To(HaveLen(1))
		Expect(server.bodies[0]).To(Equal(state))
	})

	It("exports the installed state as the engine encodes it", func(ctx SpecContext) {
		const state = `{"evaluatorID":"evaluator","serviceUID":"service","revision":"sha256:1","endpoints":{}}`
		server.responses["GET /v1/data/authz/state"] = `{"result":` + state + `}`
		Expect(client.Snapshot(ctx, target)).To(BeEquivalentTo(state))
	})

	It("exports no state from an engine without one", func(ctx SpecContext) {
		server.responses["GET /v1/data/authz/state"] = `{}`
		Expect(client.Snapshot(ctx, target)).To(BeNil())
	})

	DescribeTable("fails a request the engine doesn't answer with a document",
		func(ctx SpecContext, status int, response, message string) {
			server.status = status
			server.responses[installedPath] = response
			_, err := client.Installed(ctx, target)
			Expect(err).To(MatchError(ContainSubstring(message)))
		},
		Entry("an error status", http.StatusForbidden, "", "returned HTTP 403"),
		Entry("an undecodable response", 0, `{"result":`, "decode management response"),
		Entry("an oversized response", 0, `{"result":"`+strings.Repeat("a", 2048)+`"}`, "exceeds 1024 bytes"),
	)

	DescribeTable("refuses an engine it can't verify before sending anything",
		func(ctx SpecContext, change func(*engineclient.Target)) {
			server.responses[installedPath] = `{}`
			changed := target
			change(&changed)
			_, err := client.Installed(ctx, changed)
			Expect(err).To(HaveOccurred())
			Expect(server.requests).To(BeEmpty())
		},
		Entry("under another service's server name", func(target *engineclient.Target) { target.ServerName = "authz-other.control.svc" }),
		Entry("against roots that didn't issue its certificate", func(target *engineclient.Target) { target.Roots = x509.NewCertPool() }),
	)

	It("presents the current client certificate on every connection", func(ctx SpecContext) {
		server.responses[installedPath] = `{}`
		Expect(client.Installed(ctx, target)).To(BeZero())
		renewed, err := authority.Issue("operator-renewed", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		Expect(err).NotTo(HaveOccurred())
		certificate.Store(&renewed.TLS)
		Expect(client.Installed(ctx, target)).To(BeZero())
		Expect(server.callers).To(Equal([]string{"operator", "operator-renewed"}))
	})
})
