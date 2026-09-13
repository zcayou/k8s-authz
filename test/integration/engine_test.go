//go:build integration

package integration

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/engineclient"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("Stock OPA engine", func() {
	var fixture *engineFixture
	BeforeEach(func(ctx SpecContext) {
		fixture = startEngineFixture(ctx, false)
	})

	Context("with state installed", func() {
		var content model.ContentRevision
		BeforeEach(func(ctx SpecContext) {
			content = fixture.install(ctx, secretProhibitionProgram())
		})

		DescribeTable("refuses an admitted webhook caller on the management paths",
			func(ctx SpecContext, method, path string) {
				var body []byte
				if method == http.MethodPut {
					var err error
					body, err = json.Marshal(content)
					Expect(err).NotTo(HaveOccurred())
				}
				response := fixture.do(ctx, fixture.client(fixture.caller(utils.CallerCommonName)), method, path, body)
				Expect(response.StatusCode).To(Equal(http.StatusUnauthorized))
				Expect(response.Body.Close()).To(Succeed())
			},
			Entry("reading the state", http.MethodGet, "/v1/data/authz/state", SpecTimeout(40*time.Second)),
			Entry("reading what it serves", http.MethodGet, "/v1/data/authz/evaluator/installed", SpecTimeout(40*time.Second)),
			Entry("listing the policies", http.MethodGet, "/v1/policies", SpecTimeout(40*time.Second)),
			Entry("replacing the state", http.MethodPut, "/v1/data/authz/state", SpecTimeout(40*time.Second)),
			Entry("replacing the conditions module", http.MethodPut, "/v1/policies/k8s-authz/conditions", SpecTimeout(40*time.Second)),
		)

		It("refuses the operator's Common Name from a client CA", func(ctx SpecContext) {
			impostor, err := fixture.clientCA.Issue(managementIdentity, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			Expect(err).NotTo(HaveOccurred())
			_, err = managementClient(impostor).Installed(ctx, fixture.target)
			Expect(err).To(MatchError(ContainSubstring("returned HTTP 401")))
		}, SpecTimeout(40*time.Second))

		It("refuses another identity from the management CA", func(ctx SpecContext) {
			other, err := fixture.managementCA.Issue("other-operator", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			Expect(err).NotTo(HaveOccurred())
			_, err = managementClient(other).Installed(ctx, fixture.target)
			Expect(err).To(MatchError(ContainSubstring("returned HTTP 401")))
		}, SpecTimeout(40*time.Second))

		It("lets the operator read what it installed", func(ctx SpecContext) {
			Expect(fixture.installed(ctx).Revision).To(Equal(content.Revision))
		}, SpecTimeout(40*time.Second))

		It("becomes ready", func(ctx SpecContext) {
			Eventually(ctx, func() int { return fixture.probe("/health/ready") }).Should(Equal(http.StatusOK))
		}, SpecTimeout(40*time.Second))

		It("serves decisions", func(ctx SpecContext) {
			caller := fixture.client(fixture.caller(utils.CallerCommonName))
			for _, example := range []struct {
				resource, namespace string
				allowed             bool
			}{
				{"pods", "team", true}, {"secrets", "kube-system", false}, {"secrets", "elastic-system", true},
			} {
				decision := decode(fixture.review(ctx, caller, utils.SubjectAccessReview("admin", "list", example.resource, example.namespace)))
				Expect(decision.Status.Allowed).To(Equal(example.allowed), example.resource+" in "+example.namespace)
			}
		}, SpecTimeout(40*time.Second))

		It("answers a malformed review with a SubjectAccessReview under whenEvaluationFails", func(ctx SpecContext) {
			malformed := utils.SubjectAccessReview("admin", "list", "pods", "team")
			malformed.Spec.ResourceAttributes = nil
			decision := decode(fixture.review(ctx, fixture.client(fixture.caller(utils.CallerCommonName)), malformed))
			Expect(decision.Kind).To(Equal("SubjectAccessReview"))
			Expect(decision.Status.Allowed).To(BeFalse())
			Expect(decision.Status.Denied).To(BeTrue())
			Expect(decision.Status.EvaluationError).To(Equal("invalid SubjectAccessReview"))
		}, SpecTimeout(40*time.Second))
	})

	Context("without state", func() {
		It("reports no revision, no conditions module and no state", func(ctx SpecContext) {
			Expect(fixture.management.Installed(ctx, fixture.target)).To(BeZero())
			Expect(fixture.management.Snapshot(ctx, fixture.target)).To(BeNil())
		}, SpecTimeout(40*time.Second))

		It("stays unready", func() {
			Expect(fixture.probe("/health/ready")).NotTo(Equal(http.StatusOK))
		})

		It("leaves webhook requests to the caller's failurePolicy", func(ctx SpecContext) {
			response := fixture.review(ctx, fixture.client(fixture.caller(utils.CallerCommonName)), utils.SubjectAccessReview("admin", "list", "pods", "team"))
			Expect(response.StatusCode).NotTo(Equal(http.StatusOK))
			Expect(response.Body.Close()).To(Succeed())
		}, SpecTimeout(40*time.Second))
	})

	It("admits a new caller when its Common Name is pushed", func(ctx SpecContext) {
		prepared := secretProhibitionProgram()
		fixture.install(ctx, prepared)
		const renamed = "renamed-apiserver"
		caller := fixture.client(fixture.caller(renamed))
		review := utils.SubjectAccessReview("admin", "list", "pods", "team")
		response := fixture.review(ctx, caller, review)
		Expect(response.StatusCode).To(Equal(http.StatusUnauthorized))
		Expect(response.Body.Close()).To(Succeed())

		endpoint := prepared.Endpoints["cluster"]
		endpoint.Callers = []string{renamed}
		prepared.Endpoints["cluster"] = endpoint
		fixture.install(ctx, prepared)
		Expect(decode(fixture.review(ctx, caller, review)).Status.Allowed).To(BeTrue())
		response = fixture.review(ctx, fixture.client(fixture.caller(utils.CallerCommonName)), review)
		Expect(response.StatusCode).To(Equal(http.StatusUnauthorized))
		Expect(response.Body.Close()).To(Succeed())
	}, SpecTimeout(40*time.Second))

	It("installs and exports a service snapshot larger than one MiB", func(ctx SpecContext) {
		prepared := secretProhibitionProgram()
		prepared.Contributions["padding"] = model.Contribution{ID: "padding", Effect: model.EffectAllow, ContextID: strings.Repeat("x", 1024*1024)}
		content := fixture.install(ctx, prepared)
		encoded, err := json.Marshal(content)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(encoded)).To(BeNumerically(">", 1024*1024))
		Expect(fixture.installed(ctx).Revision).To(Equal(content.Revision))
	}, SpecTimeout(40*time.Second))
})

var _ = Describe("Stock OPA engine conditions", func() {
	const (
		inTeam  = `allow if input.request.resourceAttributes.namespace == "team"`
		inOther = `allow if input.request.resourceAttributes.namespace == "other"`
	)
	var fixture *engineFixture
	BeforeEach(func(ctx SpecContext) {
		fixture = startEngineFixture(ctx, false)
	})
	conditional := func(rules string) model.PreparedRevision {
		GinkgoHelper()
		program, err := utils.ConditionalProgram(rules)
		Expect(err).NotTo(HaveOccurred())
		return program
	}
	allowed := func(ctx SpecContext, user, namespace string) bool {
		GinkgoHelper()
		caller := fixture.client(fixture.caller(utils.CallerCommonName))
		return decode(fixture.review(ctx, caller, utils.SubjectAccessReview(user, "list", "pods", namespace))).Status.Allowed
	}

	It("installs the module and then the state, and follows a change of conditions", func(ctx SpecContext) {
		fixture.install(ctx, conditional(inTeam))
		Eventually(ctx, func() int { return fixture.probe("/health/ready") }).Should(Equal(http.StatusOK))
		Expect(allowed(ctx, "admin", "team")).To(BeTrue())
		Expect(allowed(ctx, "admin", "other")).To(BeFalse())

		// Between the module and the state push, the grant whose condition the new
		// module dropped fails closed.
		_, module, err := engine.FinalizeContent(conditional(inOther), fixture.service)
		Expect(err).NotTo(HaveOccurred())
		Expect(fixture.management.PutConditions(ctx, fixture.target, module)).To(Succeed())
		Expect(allowed(ctx, "admin", "team")).To(BeFalse())
		Expect(allowed(ctx, "admin", "other")).To(BeFalse())

		fixture.install(ctx, conditional(inOther))
		Expect(allowed(ctx, "admin", "team")).To(BeFalse())
		Expect(allowed(ctx, "admin", "other")).To(BeTrue())
	}, SpecTimeout(40*time.Second))

	It("repairs a pod holding a newer module under its revision", func(ctx SpecContext) {
		content := fixture.install(ctx, conditional(inTeam))
		_, newer, err := engine.FinalizeContent(conditional(inOther), fixture.service)
		Expect(err).NotTo(HaveOccurred())
		Expect(fixture.management.PutConditions(ctx, fixture.target, newer)).To(Succeed())
		installed, err := fixture.management.Installed(ctx, fixture.target)
		Expect(err).NotTo(HaveOccurred())
		Expect(installed).To(Equal(engineclient.Installed{Revision: content.Revision, ConditionsDigest: newer.Digest}))
		Expect(fixture.probe("/health/ready")).To(Equal(http.StatusOK))
		Expect(allowed(ctx, "admin", "team")).To(BeFalse())

		fixture.install(ctx, conditional(inTeam))
		Expect(allowed(ctx, "admin", "team")).To(BeTrue())
	}, SpecTimeout(40*time.Second))

	It("serves neither module nor state after a restart until both are pushed again", func(ctx SpecContext) {
		fixture.install(ctx, conditional(inTeam))
		fixture.restart()
		Expect(fixture.management.Installed(ctx, fixture.target)).To(BeZero())
		Expect(fixture.probe("/health/ready")).NotTo(Equal(http.StatusOK))
		fixture.install(ctx, conditional(inTeam))
		Expect(allowed(ctx, "admin", "team")).To(BeTrue())
	}, SpecTimeout(60*time.Second))

	It("fails a request on a conflicting condition only when the contribution's principal matches", func(ctx SpecContext) {
		fixture.install(ctx, conditional("allow if helper\nhelper := held if {\n\tsome held in [true, false]\n}"))
		caller := fixture.client(fixture.caller(utils.CallerCommonName))
		response := fixture.review(ctx, caller, utils.SubjectAccessReview("admin", "list", "pods", "team"))
		Expect(response.StatusCode).To(Equal(http.StatusInternalServerError))
		Expect(response.Body.Close()).To(Succeed())
		Expect(allowed(ctx, "bob", "team")).To(BeFalse())
		outside := decode(fixture.review(ctx, caller, utils.SubjectAccessReview("admin", "list", "secrets", "team")))
		Expect(outside.Status.Allowed).To(BeFalse())
	}, SpecTimeout(40*time.Second))
})
