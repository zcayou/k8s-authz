package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	apiserverload "k8s.io/apiserver/pkg/apis/apiserver/load"
	apiservervalidation "k8s.io/apiserver/pkg/apis/apiserver/validation"
	authorizationcel "k8s.io/apiserver/pkg/authorization/cel"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
)

var _ = Describe("render-caller-config", func() {
	It("emits native-valid path-only caller configuration with exact recovery exclusions", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		servicePath := writeServiceFixture(directory, healthyService())
		webhookPath := filepath.Join(directory, "installed", "webhook.kubeconfig")
		Expect(os.MkdirAll(filepath.Dir(webhookPath), 0o755)).To(Succeed())
		Expect(os.WriteFile(webhookPath, []byte("placeholder"), 0o600)).To(Succeed())
		args := []string{
			"render-caller-config", "--service-file", servicePath, "--endpoint", "trace", "--webhook-server", "https://10.245.0.11:443",
			"--caller-certificate", "/etc/kubernetes/pki/authz.crt", "--caller-key", "/etc/kubernetes/pki/authz.key",
			"--engine-ca", "/etc/kubernetes/pki/authz-ca.crt", "--webhook-kubeconfig-path", webhookPath,
			"--recovery-user", `root\"operator`, "--recovery-group", `system:authz\\recovery`,
		}
		code, stdout, stderr := execute(ctx, "", args...)
		Expect(code).To(Equal(0), stderr)
		parts := bytes.SplitN(stdout, []byte("---\n"), 2)
		Expect(parts).To(HaveLen(2))

		kubeconfig, err := clientcmd.Load(parts[0])
		Expect(err).NotTo(HaveOccurred())
		cluster := kubeconfig.Clusters["k8s-authz"]
		Expect(cluster.Server).To(Equal("https://10.245.0.11:443/v0/data/authz/endpoints/trace/decision"))
		Expect(cluster.CertificateAuthority).To(Equal("/etc/kubernetes/pki/authz-ca.crt"))
		Expect(cluster.CertificateAuthorityData).To(BeEmpty())
		Expect(cluster.TLSServerName).To(Equal("authz-fleet-authz." + "control" + ".svc"))
		authInfo := kubeconfig.AuthInfos["k8s-authz"]
		Expect(authInfo.ClientCertificate).To(Equal("/etc/kubernetes/pki/authz.crt"))
		Expect(authInfo.ClientKey).To(Equal("/etc/kubernetes/pki/authz.key"))
		Expect(authInfo.ClientCertificateData).To(BeEmpty())
		Expect(authInfo.ClientKeyData).To(BeEmpty())

		loaded, err := apiserverload.LoadFromData(parts[1])
		Expect(err).NotTo(HaveOccurred())
		problems := apiservervalidation.ValidateAuthorizationConfiguration(
			authorizationcel.NewDefaultCompiler(),
			field.NewPath("authorizationConfiguration"),
			loaded,
			sets.New("Webhook", "Node", "RBAC"),
			sets.New("Webhook"),
		)
		Expect(problems).To(BeEmpty())
		Expect(loaded.Authorizers).To(HaveLen(3))
		Expect(string(loaded.Authorizers[0].Type)).To(Equal("Webhook"))
		Expect(loaded.Authorizers[0].Name).To(Equal("trace.fleet-authz.control.k8s-authz"))
		Expect(string(loaded.Authorizers[1].Type)).To(Equal("Node"))
		Expect(string(loaded.Authorizers[2].Type)).To(Equal("RBAC"))
		webhook := loaded.Authorizers[0].Webhook
		Expect(webhook.FailurePolicy).To(Equal("Deny"))
		Expect(webhook.Timeout.Duration).To(Equal(3 * time.Second))
		Expect(webhook.SubjectAccessReviewVersion).To(Equal("v1"))
		Expect(webhook.MatchConditionSubjectAccessReviewVersion).To(Equal("v1"))
		Expect(webhook.CacheAuthorizedRequests).To(BeTrue())
		Expect(webhook.AuthorizedTTL.Duration).To(Equal(5 * time.Minute))
		Expect(webhook.CacheUnauthorizedRequests).To(BeTrue())
		Expect(webhook.UnauthorizedTTL.Duration).To(Equal(30 * time.Second))
		Expect(webhook.MatchConditions).To(HaveLen(2))
	})

	DescribeTable("sets the webhook failurePolicy from the endpoint's whenEvaluationFails",
		func(ctx SpecContext, fallback string) {
			service := healthyService()
			service.Spec.Endpoints[0].WhenEvaluationFails = api.DecisionFallback(fallback)
			code, stdout, stderr := execute(ctx, "", renderArgs(writeServiceFixture(GinkgoT().TempDir(), service), "/etc/kubernetes/authz.kubeconfig")...)
			Expect(code).To(Equal(0), stderr)
			parts := bytes.SplitN(stdout, []byte("---\n"), 2)
			Expect(parts).To(HaveLen(2))
			loaded, err := apiserverload.LoadFromData(parts[1])
			Expect(err).NotTo(HaveOccurred())
			Expect(loaded.Authorizers[0].Webhook.FailurePolicy).To(Equal(fallback))
		},
		Entry("Deny", "Deny"),
		Entry("NoOpinion", "NoOpinion"),
	)

	It("writes both artifacts with restrictive kubeconfig permissions", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		servicePath := writeServiceFixture(directory, healthyService())
		outputDirectory := filepath.Join(directory, "output")
		webhookPath := filepath.Join(outputDirectory, "webhook.kubeconfig")
		Expect(os.Mkdir(outputDirectory, 0o755)).To(Succeed())
		Expect(os.WriteFile(webhookPath, []byte("old"), 0o644)).To(Succeed())
		args := renderArgs(servicePath, webhookPath)
		args = append(args, "--output-dir", outputDirectory)
		code, _, stderr := execute(ctx, "", args...)
		Expect(code).To(Equal(0), stderr)
		info, err := os.Stat(webhookPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))
		_, err = os.Stat(filepath.Join(outputDirectory, "authorization-config.yaml"))
		Expect(err).NotTo(HaveOccurred())
	})

	It("caches decisions for the requested TTLs", func(ctx SpecContext) {
		args := append(renderArgs(writeServiceFixture(GinkgoT().TempDir(), healthyService()), "/etc/kubernetes/authz.kubeconfig"), "--authorized-ttl", "1m", "--unauthorized-ttl", "0s")
		code, stdout, stderr := execute(ctx, "", args...)
		Expect(code).To(Equal(0), stderr)
		parts := bytes.SplitN(stdout, []byte("---\n"), 2)
		Expect(parts).To(HaveLen(2))
		loaded, err := apiserverload.LoadFromData(parts[1])
		Expect(err).NotTo(HaveOccurred())
		webhook := loaded.Authorizers[0].Webhook
		Expect(webhook.CacheAuthorizedRequests).To(BeTrue())
		Expect(webhook.AuthorizedTTL.Duration).To(Equal(time.Minute))
		Expect(webhook.CacheUnauthorizedRequests).To(BeFalse())
	})

	It("refuses every webhook server that isn't a bare HTTPS origin", func(ctx SpecContext) {
		for _, server := range []string{
			"",
			"http://10.245.0.11",
			"https://user@10.245.0.11",
			"https://10.245.0.11/prefix",
			"https://10.245.0.11?x=1",
		} {
			args := renderArgs(writeServiceFixture(GinkgoT().TempDir(), healthyService()), "/etc/kubernetes/authz.kubeconfig")
			args[slices.Index(args, "--webhook-server")+1] = server
			code, _, stderr := execute(ctx, "", args...)
			Expect(code).To(Equal(2), server)
			Expect(stderr).To(ContainSubstring("--webhook-server"), server)
		}
	})

	It("reads the named AuthorizationService from the namespace -n selects", func(ctx SpecContext) {
		service := healthyService()
		server := newFakeAPIServer("", &service)
		directory := GinkgoT().TempDir()
		kubeconfig := server.kubeconfig(directory, callerToken)
		args := slices.Concat([]string{"render-caller-config", service.Name, "-n", "control", "--kubeconfig", kubeconfig}, renderArgs("", "/etc/kubernetes/authz.kubeconfig")[3:])
		code, stdout, stderr := execute(ctx, "", args...)
		Expect(code).To(Equal(0), stderr)
		rendered, err := clientcmd.Load(bytes.SplitN(stdout, []byte("---\n"), 2)[0])
		Expect(err).NotTo(HaveOccurred())
		Expect(rendered.Clusters["k8s-authz"].TLSServerName).To(Equal("authz-fleet-authz." + "control" + ".svc"))
		_, tokens := server.observed()
		Expect(tokens).To(HaveEach("Bearer " + callerToken))

		code, _, stderr = execute(ctx, "", slices.Concat([]string{"render-caller-config", "absent", "-n", "control", "--kubeconfig", kubeconfig}, renderArgs("", "/etc/kubernetes/authz.kubeconfig")[3:])...)
		Expect(code).To(Equal(2))
		Expect(stderr).To(ContainSubstring("not found"))
	})

	It("takes kubectl's connection flags", func(ctx SpecContext) {
		service := healthyService()
		server := newFakeAPIServer("", &service)
		directory := GinkgoT().TempDir()
		args := slices.Concat([]string{"render-caller-config", service.Name, "-n", "control", "--kubeconfig", server.kubeconfig(directory, "stale-token"), "--token", callerToken}, renderArgs("", "/etc/kubernetes/authz.kubeconfig")[3:])
		code, _, stderr := execute(ctx, "", args...)
		Expect(code).To(Equal(0), stderr)
		_, tokens := server.observed()
		Expect(tokens).To(HaveEach("Bearer " + callerToken))
	})

	It("renders without recovery identities", func(ctx SpecContext) {
		args := renderArgs(writeServiceFixture(GinkgoT().TempDir(), healthyService()), "/etc/kubernetes/authz.kubeconfig")
		args = slices.Delete(args, slices.Index(args, "--recovery-user"), slices.Index(args, "--recovery-user")+2)
		code, stdout, stderr := execute(ctx, "", args...)
		Expect(code).To(Equal(0), stderr)
		loaded, err := apiserverload.LoadFromData(bytes.SplitN(stdout, []byte("---\n"), 2)[1])
		Expect(err).NotTo(HaveOccurred())
		Expect(loaded.Authorizers[0].Webhook.MatchConditions).To(BeEmpty())
	})

	It("strictly decodes the service file", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		path := writeServiceFixture(directory, healthyService())
		data, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(path, append(data, "surprise: true\n"...), 0o600)).To(Succeed())
		code, _, stderr := execute(ctx, "", renderArgs(path, "/etc/kubernetes/authz.kubeconfig")...)
		Expect(code).To(Equal(2))
		Expect(stderr).To(ContainSubstring("surprise"))
	})

	DescribeTable("refuses inconsistent inputs", func(ctx SpecContext, message string, edit func([]string) []string) {
		code, stdout, stderr := execute(ctx, "", edit(renderArgs(writeServiceFixture(GinkgoT().TempDir(), healthyService()), "/etc/kubernetes/authz.kubeconfig"))...)
		Expect(code).To(Equal(2))
		Expect(stdout).To(BeEmpty())
		Expect(stderr).To(ContainSubstring(message))
	},
		Entry("a service file with a name", "unknown command", func(args []string) []string { return slices.Insert(args, 1, "fleet-authz") }),
		Entry("a service file with a namespace", "service-file", func(args []string) []string { return append(args, "-n", "control") }),
		Entry("a service file with a token", "service-file", func(args []string) []string { return append(args, "--token", callerToken) }),
		Entry("neither a service file nor a name", "accepts 1 arg", func(args []string) []string { return slices.Delete(args, 1, 3) }),
		Entry("no endpoint", "endpoint", func(args []string) []string { return slices.Delete(args, 3, 5) }),
		Entry("an undeclared endpoint", "not declared", func(args []string) []string {
			args[slices.Index(args, "--endpoint")+1] = "absent"
			return args
		}),
		Entry("a relative caller key", "--caller-key", func(args []string) []string {
			args[slices.Index(args, "--caller-key")+1] = "caller.key"
			return args
		}),
		Entry("too many recovery identities", "64", func(args []string) []string {
			for range 64 {
				args = append(args, "--recovery-group", "group")
			}
			return args
		}),
	)
})

func healthyService() api.AuthorizationService {
	return api.AuthorizationService{
		TypeMeta:   metav1.TypeMeta{APIVersion: "authorization.zctx.io/v1alpha1", Kind: "AuthorizationService"},
		ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: "fleet-authz", Generation: 1},
		Spec: api.AuthorizationServiceSpec{
			Runtime: api.AuthorizationServiceRuntime{Type: api.RuntimeTypeDeployment, Deployment: &api.DeploymentRuntime{Replicas: 2}, MinReadyReplicas: 1},
			TLS: api.AuthorizationServiceTLS{
				Server: api.ServerTLS{
					SecretRef: api.SecretReference{Name: "server-tls"},
					CARef:     api.CABundleRef{SecretKeyRef: &api.SecretKeyRef{Name: "serving-ca", Key: "ca.crt"}},
				},
				Client: api.ClientTLS{CARef: api.CABundleRef{SecretKeyRef: &api.SecretKeyRef{Name: "client-ca", Key: "ca.crt"}}},
			},
			Program: api.AuthorizationProgram{Type: "Kubernetes"},
			Endpoints: []api.Endpoint{{
				Name:                "trace",
				Callers:             []api.Caller{{CommonName: "kube-apiserver"}},
				SourceRefs:          []api.SourceRef{{Namespace: "control", Name: "platform"}},
				Authorities:         []api.Authority{},
				WhenEvaluationFails: "Deny",
			}},
		},
	}
}

func writeServiceFixture(directory string, service api.AuthorizationService) string {
	GinkgoHelper()
	data, err := yaml.Marshal(service)
	Expect(err).NotTo(HaveOccurred())
	path := filepath.Join(directory, "service.yaml")
	Expect(os.WriteFile(path, data, 0o600)).To(Succeed())
	return path
}

func renderArgs(servicePath, webhookPath string) []string {
	return []string{
		"render-caller-config", "--service-file", servicePath, "--endpoint", "trace", "--webhook-server", "https://10.245.0.11:443",
		"--caller-certificate", "/pki/caller.crt", "--caller-key", "/pki/caller.key", "--engine-ca", "/pki/ca.crt",
		"--webhook-kubeconfig-path", webhookPath, "--recovery-user", "admin",
	}
}
