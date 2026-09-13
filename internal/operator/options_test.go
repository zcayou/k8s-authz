package operator_test

import (
	"flag"
	"io"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/operator"
)

var pinnedEngineImage = "example.invalid/opa@sha256:" + strings.Repeat("a", 64)

func parseOptions(arguments ...string) (operator.Options, error) {
	var options operator.Options
	flags := flag.NewFlagSet("operator", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	options.BindFlags(flags)
	return options, flags.Parse(arguments)
}

var _ = Describe("Operator options", func() {
	It("defaults to every namespace, the pinned stock engine, disabled decision logs, the diagnostics port and two minutes of push failures", func() {
		options, err := parseOptions()
		Expect(err).NotTo(HaveOccurred())
		Expect(options).To(Equal(operator.Options{EngineImage: engine.DefaultImage, DiagnosticsBindAddress: ":9443", RemediationAfter: 2 * time.Minute}))
	})

	It("parses every flag", func() {
		options, err := parseOptions(
			"--control-namespaces=second,control,second",
			"--engine-image="+pinnedEngineImage,
			"--engine-decision-logs",
			"--management-cert-path=/certs/management",
			"--management-ca-path=/certs/management-ca/ca.crt",
			"--diagnostics-bind-address=127.0.0.1:9444",
			"--diagnostics-cert-path=/certs/diagnostics",
			"--remediation-after=30s",
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(options).To(Equal(operator.Options{
			ControlNamespaces:      []string{"control", "second"},
			EngineImage:            pinnedEngineImage,
			EngineDecisionLogs:     true,
			ManagementCertPath:     "/certs/management",
			ManagementCAPath:       "/certs/management-ca/ca.crt",
			DiagnosticsBindAddress: "127.0.0.1:9444",
			DiagnosticsCertPath:    "/certs/diagnostics",
			RemediationAfter:       30 * time.Second,
		}))
		Expect(options.Validate()).To(Succeed())
	})

	It("treats an empty namespace list as every namespace", func() {
		options, err := parseOptions("--control-namespaces=")
		Expect(err).NotTo(HaveOccurred())
		Expect(options.ControlNamespaces).To(BeEmpty())
	})

	DescribeTable("rejects an invalid namespace list", func(value string) {
		_, err := parseOptions("--control-namespaces=" + value)
		Expect(err).To(MatchError(ContainSubstring("control-namespaces")))
	},
		Entry("an empty element", "control,"),
		Entry("an invalid name", "Control"),
	)

	It("requires the certificate paths", func() {
		options, err := parseOptions()
		Expect(err).NotTo(HaveOccurred())
		err = options.Validate()
		for _, name := range []string{"management-cert-path", "management-ca-path", "diagnostics-cert-path"} {
			Expect(err).To(MatchError(ContainSubstring("--" + name + " is required")))
		}
		Expect(err).NotTo(MatchError(ContainSubstring("engine-image")))
	})

	It("rejects a negative remediation delay", func() {
		options, err := parseOptions(
			"--remediation-after=-1s",
			"--management-cert-path=/certs/management",
			"--management-ca-path=/certs/management-ca/ca.crt",
			"--diagnostics-cert-path=/certs/diagnostics",
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(options.Validate()).To(MatchError(ContainSubstring("--remediation-after")))
	})

	It("rejects an engine image that is not pinned by digest", func() {
		options, err := parseOptions(
			"--engine-image=example.invalid/opa:latest",
			"--management-cert-path=/certs/management",
			"--management-ca-path=/certs/management-ca/ca.crt",
			"--diagnostics-cert-path=/certs/diagnostics",
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(options.Validate()).To(MatchError(ContainSubstring("--engine-image")))
	})
})
