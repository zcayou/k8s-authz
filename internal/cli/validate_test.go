package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
)

var _ = Describe("validate", func() {
	It("reports conservative exclusions as warnings while retaining success", func(ctx SpecContext) {
		input := `{"apiVersion":"authorization.zctx.io/v1alpha1","kind":"Policy","metadata":{"namespace":"tenant","name":"operator"},"spec":{"include":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}],"exclude":[{"apiGroups":["*"],"resources":["*"],"verbs":["delete"],"namespaces":["kube-system"]}]}}`
		code, stdout, stderr := execute(ctx, input, "validate", "documents", "--source", "control/platform", "-o", "json", "-")
		Expect(code).To(BeZero(), stderr)
		var report validationReport
		Expect(json.Unmarshal(stdout, &report)).To(Succeed())
		Expect(report.Valid).To(BeTrue())
		Expect(report.Diagnostics).To(HaveLen(1))
		Expect(report.Diagnostics[0].Severity).To(Equal(api.IssueSeverityWarning))
		Expect(report.Diagnostics[0].Reason).To(Equal(model.ReasonNamespaceScopeConservative))
	})
	It("strictly validates multiple custom and native documents offline", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		path := filepath.Join(directory, "policies.yaml")
		contents := `apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: tenant
  name: pod-reader
spec:
  include:
    - verbs: [get]
      apiGroups: [""]
      resources: [pods]
      namespaces: [tenant]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: discovery
rules:
  - verbs: [get]
    apiGroups: [""]
    resources: [namespaces]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: system:auth-delegator
rules:
  - verbs: [create]
    apiGroups: [authentication.k8s.io]
    resources: [tokenreviews]
`
		Expect(os.WriteFile(path, []byte(contents), 0o600)).To(Succeed())
		code, stdout, stderr := execute(ctx, "", "validate", "documents", "--source", "control/platform", "--output", "json", path)
		Expect(code).To(Equal(0), stderr)
		var report validationReport
		Expect(json.Unmarshal(stdout, &report)).To(Succeed())
		Expect(report.Valid).To(BeTrue())
		Expect(report.Documents).To(Equal(3))
		Expect(report.Diagnostics).To(BeEmpty())
	})

	DescribeTable("validates metadata as the API server does for the document's kind", func(ctx SpecContext, document, message string) {
		code, stdout, _ := execute(ctx, document, "validate", "documents", "--source", "control/platform", "-o", "json", "-")
		Expect(code).To(Equal(1))
		var report validationReport
		Expect(json.Unmarshal(stdout, &report)).To(Succeed())
		Expect(report.Diagnostics).To(ConsistOf(And(
			HaveField("Reason", model.ReasonInvalid),
			HaveField("FieldPath", "metadata.name"),
			HaveField("Message", ContainSubstring(message)),
		)))
	},
		Entry("an RBAC name that isn't a path segment",
			`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"system/auth-delegator"},"rules":[]}`, `may not contain '/'`),
		Entry("a policy name that isn't a DNS subdomain",
			`{"apiVersion":"authorization.zctx.io/v1alpha1","kind":"Policy","metadata":{"namespace":"tenant","name":"system:reader"},"spec":{"include":[]}}`, "RFC 1123 subdomain"),
	)

	It("rejects duplicate keys before typed decoding and attributes the offline source", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		path := filepath.Join(directory, "invalid.yaml")
		contents := `apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: tenant
  name: reader
spec:
  include:
    - verbs: [get]
      verbs: [list]
      apiGroups: [""]
      resources: [pods]
`
		Expect(os.WriteFile(path, []byte(contents), 0o600)).To(Succeed())
		code, stdout, _ := execute(ctx, "", "validate", "documents", "--source", "control/platform", "-o", "json", path)
		Expect(code).To(Equal(1))
		var report validationReport
		Expect(json.Unmarshal(stdout, &report)).To(Succeed())
		Expect(report.Valid).To(BeFalse())
		Expect(report.Diagnostics).To(HaveLen(1))
		Expect(report.Diagnostics[0].Reason).To(Equal(model.IssueReason("InvalidSyntax")))
		Expect(report.Diagnostics[0].Message).To(ContainSubstring("already set"))
	})

	It("rejects unknown policy fields and attributes them to the assigned source", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		path := filepath.Join(directory, "unknown.yaml")
		contents := `apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata: {namespace: tenant, name: reader}
spec:
  include: []
  surprise: true
`
		Expect(os.WriteFile(path, []byte(contents), 0o600)).To(Succeed())
		code, stdout, _ := execute(ctx, "", "validate", "documents", "--source", "control/platform", "-o", "json", path)
		Expect(code).To(Equal(1))
		var report validationReport
		Expect(json.Unmarshal(stdout, &report)).To(Succeed())
		Expect(report.Diagnostics).To(HaveLen(1))
		Expect(report.Diagnostics[0].Source).To(Equal(&model.SourceKey{Namespace: "control", Name: "platform"}))
		Expect(report.Diagnostics[0].Reason).To(Equal(model.ReasonInvalid))
		Expect(report.Diagnostics[0].Message).To(ContainSubstring(`unknown field "spec.surprise"`))
	})

	It("detects duplicate source-qualified identities across files", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		document := `apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySet
metadata: {namespace: tenant, name: root}
spec:
  bindingRefs: []
  prohibitionRefs: []
`
		first := filepath.Join(directory, "a.yaml")
		second := filepath.Join(directory, "b.yaml")
		Expect(os.WriteFile(first, []byte(document), 0o600)).To(Succeed())
		Expect(os.WriteFile(second, []byte(document), 0o600)).To(Succeed())
		code, stdout, _ := execute(ctx, "", "validate", "documents", "--source", "control/platform", "-o", "json", second, first)
		Expect(code).To(Equal(1))
		var report validationReport
		Expect(json.Unmarshal(stdout, &report)).To(Succeed())
		Expect(report.Diagnostics).To(HaveLen(1))
		Expect(report.Diagnostics[0].Reason).To(Equal(model.IssueReason("DuplicateDocument")))
	})

	It("rejects a PolicySource field the schema doesn't declare without requiring --source", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		path := filepath.Join(directory, "source.yaml")
		contents := `apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySource
metadata: {namespace: control, name: platform}
spec:
  provider: {type: Kubernetes}
  collection: []
  unknown: true
`
		Expect(os.WriteFile(path, []byte(contents), 0o600)).To(Succeed())
		code, stdout, _ := execute(ctx, "", "validate", "documents", "-o", "json", path)
		Expect(code).To(Equal(1))
		Expect(string(stdout)).To(ContainSubstring("unknown"))
	})

	It("returns unavailable for unreadable input and does not emit a report", func(ctx SpecContext) {
		code, stdout, stderr := execute(ctx, "", "validate", "documents", filepath.Join(GinkgoT().TempDir(), "missing"))
		Expect(code).To(Equal(2))
		Expect(stdout).To(BeEmpty())
		Expect(stderr).To(ContainSubstring("read"))
	})

	It("produces deterministic diagnostics independent of file argument order", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		for _, name := range []string{"a", "b"} {
			contents := strings.ReplaceAll(`apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata: {namespace: tenant, name: NAME}
spec: {include: [], surprise: true}
`, "NAME", name)
			Expect(os.WriteFile(filepath.Join(directory, name+".yaml"), []byte(contents), 0o600)).To(Succeed())
		}
		run := func(files ...string) string {
			code, stdout, _ := execute(ctx, "", append([]string{"validate", "documents", "--source", "control/platform", "-o", "json"}, files...)...)
			Expect(code).To(Equal(1))
			return string(stdout)
		}
		a := filepath.Join(directory, "a.yaml")
		b := filepath.Join(directory, "b.yaml")
		Expect(run(a, b)).To(Equal(run(b, a)))
	})

	It("completes the output formats", func(ctx SpecContext) {
		code, stdout, stderr := execute(ctx, "", "__complete", "validate", "documents", "-o", "")
		Expect(code).To(BeZero(), stderr)
		Expect(strings.Fields(string(stdout))).To(ContainElements("text", "json"))
	})
})
