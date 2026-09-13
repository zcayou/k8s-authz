package cli_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/validation"
	"github.com/zcayou/k8s-authz/test/utils"
)

const (
	testRootBinding = `apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata: {namespace: policies, name: root}
spec:
  subjectMatch: {}
  policyRef: {name: empty}
`
	testEmptyPolicyDocument = `apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata: {namespace: policies, name: empty}
spec:
  include: []
`
	graphSourceFlag = "control/platform="
)

var _ = Describe("graph validation", func() {
	var directory, servicePath string
	BeforeEach(func() {
		directory = GinkgoT().TempDir()
		servicePath = writeServiceFixture(directory, graphService())
	})
	validateGraph := func(ctx SpecContext, args ...string) (int, validationReport, string) {
		GinkgoHelper()
		code, stdout, stderr := execute(ctx, "", append([]string{"validate", "graph", "-o", "json", servicePath}, args...)...)
		var report validationReport
		if len(stdout) != 0 {
			Expect(json.Unmarshal(stdout, &report)).To(Succeed())
		}
		return code, report, stderr
	}

	It("compiles the service against the documents each source maps", func(ctx SpecContext) {
		code, report, stderr := validateGraph(ctx, "--source", graphSourceFlag+writeFile(directory, "root.yaml", testRootBinding), "--source", graphSourceFlag+writeFile(directory, "policy.yaml", testEmptyPolicyDocument))
		Expect(code).To(Equal(0), stderr)
		Expect(report.Valid).To(BeTrue())
		Expect(report.Documents).To(Equal(3))
		Expect(report.Diagnostics).To(BeEmpty())
	})

	It("reports a root its source doesn't hold as missing", func(ctx SpecContext) {
		code, report, _ := validateGraph(ctx, "--source", graphSourceFlag+writeFile(directory, "policy.yaml", testEmptyPolicyDocument))
		Expect(code).To(Equal(1))
		Expect(report.Valid).To(BeFalse())
		Expect(report.Diagnostics).To(ContainElement(HaveField("Reason", model.ReasonMissingReference)))
	})

	It("rejects unknown source document fields with source-qualified attribution", func(ctx SpecContext) {
		code, report, _ := validateGraph(ctx, "--source", graphSourceFlag+writeFile(directory, "root.yaml", testRootBinding+"unexpected: true\n"), "--source", graphSourceFlag+writeFile(directory, "policy.yaml", testEmptyPolicyDocument))
		Expect(code).To(Equal(1))
		Expect(report.Diagnostics).To(ContainElement(And(HaveField("Reason", model.ReasonInvalid), HaveField("Source.Name", "platform"), HaveField("File", HaveSuffix("root.yaml")))))
	})

	It("compiles the documents that have errors, as the operator does", func(ctx SpecContext) {
		code, report, _ := validateGraph(ctx, "--source", graphSourceFlag+writeFile(directory, "root.yaml", testRootBinding), "--source", graphSourceFlag+writeFile(directory, "policy.yaml", testEmptyPolicyDocument+"unexpected: true\n"))
		Expect(code).To(Equal(1))
		Expect(report.Diagnostics).To(ContainElement(And(HaveField("Reason", model.ReasonInvalid), HaveField("File", HaveSuffix("policy.yaml")))))
		Expect(report.Diagnostics).To(ContainElement(And(HaveField("Reason", model.ReasonInvalidDocument), HaveField("File", servicePath), HaveField("Endpoint", "trace"))))
	})

	It("rejects one document mapped to a source twice", func(ctx SpecContext) {
		root := writeFile(directory, "root.yaml", testRootBinding)
		code, report, _ := validateGraph(ctx, "--source", graphSourceFlag+root, "--source", graphSourceFlag+root)
		Expect(code).To(Equal(1))
		Expect(report.Diagnostics).To(ContainElement(HaveField("Reason", model.IssueReason("DuplicateDocument"))))
	})

	DescribeTable("refuses malformed source mappings", func(ctx SpecContext, mapping, message string) {
		code, report, stderr := validateGraph(ctx, "--source", mapping)
		Expect(code).To(Equal(2))
		Expect(report).To(BeZero())
		Expect(stderr).To(ContainSubstring(message))
	},
		Entry("no file", "control/platform", "NAMESPACE/NAME=FILE"),
		Entry("an empty file", graphSourceFlag, "NAMESPACE/NAME=FILE"),
		Entry("no namespace", "platform=root.yaml", "NAMESPACE/NAME"),
		Entry("a missing file", graphSourceFlag+"absent.yaml", "absent.yaml"),
	)

	Describe("Rego conditions", func() {
		conditionalPolicy := func(rego string) string {
			return writeFile(directory, "policy.yaml", `apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata: {namespace: policies, name: empty}
spec:
  condition:
    rego: |
      package condition
      `+rego+`
`)
		}
		sources := func(policy string) []string {
			return []string{"--source", graphSourceFlag + writeFile(directory, "root.yaml", testRootBinding), "--source", graphSourceFlag + policy}
		}

		It("refuses a condition in a source --rego-source doesn't name", func(ctx SpecContext) {
			code, report, _ := validateGraph(ctx, sources(conditionalPolicy(`allow if startswith(input.principal.user, "a")`))...)
			Expect(code).To(Equal(1))
			Expect(report.Diagnostics).To(ContainElement(HaveField("Reason", model.ReasonRegoNotAllowed)))
		})

		It("gives a named source the default builtins", func(ctx SpecContext) {
			code, report, stderr := validateGraph(ctx, append(sources(conditionalPolicy(`allow if startswith(input.principal.user, "a")`)), "--rego-source", "control/platform")...)
			Expect(code).To(Equal(0), stderr)
			Expect(report.Diagnostics).To(ConsistOf(HaveField("Reason", model.ReasonUniversalEnvelope)))
		})

		It("gives a named source exactly the listed builtins", func(ctx SpecContext) {
			code, report, _ := validateGraph(ctx, append(sources(conditionalPolicy(`allow if startswith(input.principal.user, "a")`)), "--rego-source", "control/platform=endswith")...)
			Expect(code).To(Equal(1))
			Expect(report.Diagnostics).To(ContainElement(And(HaveField("Reason", model.ReasonBuiltinNotAllowed), HaveField("Message", ContainSubstring("startswith")))))

			code, _, stderr := validateGraph(ctx, append(sources(conditionalPolicy(`allow if startswith(input.principal.user, "a")`)), "--rego-source", "control/platform=endswith,startswith")...)
			Expect(code).To(Equal(0), stderr)
		})

		DescribeTable("refuses malformed --rego-source values", func(ctx SpecContext, value, message string) {
			code, report, stderr := validateGraph(ctx, append(sources(conditionalPolicy(`allow if true`)), "--rego-source", value)...)
			Expect(code).To(Equal(2))
			Expect(report).To(BeZero())
			Expect(stderr).To(ContainSubstring(message))
		},
			Entry("a source no --source assigns", "control/other", "--rego-source names control/other, which no --source assigns"),
			Entry("an undefined builtin", "control/platform=no.such.builtin", "no.such.builtin isn't a builtin this release defines"),
			Entry("no namespace", "platform", "NAMESPACE/NAME"),
		)
	})

	It("requires the service file to hold one AuthorizationService", func(ctx SpecContext) {
		servicePath = writeFile(directory, "service.yaml", testEmptyPolicyDocument)
		code, report, _ := validateGraph(ctx)
		Expect(code).To(Equal(1))
		Expect(report.Diagnostics).To(ConsistOf(HaveField("Reason", model.IssueReason("InvalidGraphInput"))))
	})
})

var _ = Describe("Delegated hierarchy", func() {
	var service []byte
	var sources map[model.SourceKey][]byte
	BeforeEach(func() {
		service, sources = hierarchy()
	})

	It("validates as a complete graph", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		args := make([]string, 0, 6+2*len(sources))
		args = append(args, "validate", "graph", "-o", "json", writeFile(directory, "service.yaml", string(service)))
		for key, documents := range sources {
			args = append(args, "--source", key.Namespace+"/"+key.Name+"="+writeFile(directory, key.Name+".yaml", string(documents)))
		}
		code, stdout, stderr := execute(ctx, "", args...)
		Expect(code).To(Equal(0), stderr)
		var report validationReport
		Expect(json.Unmarshal(stdout, &report)).To(Succeed())
		Expect(report.Valid).To(BeTrue(), "%v", report.Diagnostics)
		Expect(report.Diagnostics).To(HaveEach(HaveField("Severity", api.IssueSeverityWarning)))
	})

	DescribeTable("enforces the hierarchy", func(ctx SpecContext, group, verb, apiGroup, resource, namespace string, expected model.Result) {
		prepared := compileHierarchy(service, sources)
		review := authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
			Spec:     authorizationv1.SubjectAccessReviewSpec{User: "example-user", Groups: []string{group}, ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: verb, Group: apiGroup, Version: "v1", Resource: resource, Namespace: namespace}},
		}
		evaluation, err := utils.Evaluate(ctx, prepared, "trace", review)
		Expect(err).NotTo(HaveOccurred())
		Expect(evaluation.Decision.EvaluationError).To(BeEmpty())
		Expect(evaluation.Decision.Result).To(Equal(expected))
	},
		Entry("ELK administers delegated namespaces", "oidc:elk-a", "delete", "apps", "deployments", "elastic-system", model.Result("Allow")),
		Entry("ELK includes extension APIs", "oidc:elk-a", "create", "operator.example", "clusters", "confluent", model.Result("Allow")),
		Entry("ELK cannot escape the bound", "oidc:elk-a", "list", "", "secrets", "unrelated", model.Result("Deny")),
		Entry("ELK cannot read all namespaces", "oidc:elk-a", "list", "", "secrets", "", model.Result("Deny")),
		Entry("ELK reads secrets inside its namespace", "oidc:elk-a", "list", "", "secrets", "elastic-system", model.Result("Allow")),
		Entry("native viewer reads workloads", "oidc:elk-v", "list", "apps", "deployments", "confluent", model.Result("Allow")),
		Entry("native viewer cannot delete workloads", "oidc:elk-v", "delete", "apps", "deployments", "confluent", model.Result("Deny")),
		Entry("native viewer cannot read secrets", "oidc:elk-v", "list", "", "secrets", "elastic-system", model.Result("Deny")),
		Entry("subdelegation permits application reads", "oidc:elk-app-r", "list", "apps", "deployments", "confluent", model.Result("Allow")),
		Entry("subdelegation cannot permit deletes", "oidc:elk-app-r", "delete", "apps", "deployments", "confluent", model.Result("Deny")),
		Entry("platform administrators remain prohibited", "oidc:k8s-platform-admins", "list", "", "secrets", "kube-system", model.Result("Deny")),
		Entry("prohibition covers cluster-wide collection", "oidc:k8s-platform-admins", "list", "", "secrets", "", model.Result("Deny")),
		Entry("independent root administrator falls through", "oidc:k8s-root-admins", "list", "", "secrets", "", model.Result("NoOpinion")),
	)
})

// graphService is an AuthorizationService whose one authority's root
// is policies/root in control/platform.
func graphService() api.AuthorizationService {
	service := healthyService()
	source := api.SourceRef{Namespace: "control", Name: "platform"}
	service.Spec.Endpoints[0].Authorities = []api.Authority{{BindingRef: api.BindingRef{SourceRef: &source, Namespace: "policies", Name: "root"}, WhenNoPolicyAllows: "NoOpinion"}}
	return service
}

func writeFile(directory, name, contents string) string {
	GinkgoHelper()
	path := filepath.Join(directory, name)
	Expect(os.WriteFile(path, []byte(contents), 0o600)).To(Succeed())
	return path
}

// hierarchy returns testdata/hierarchy's AuthorizationService and documents
// by source. The platform root delegates to the orchestration team's subtree,
// which subdelegates to an application team.
func hierarchy() ([]byte, map[model.SourceKey][]byte) {
	GinkgoHelper()
	directory := filepath.Join("testdata", "hierarchy")
	service, err := os.ReadFile(filepath.Join(directory, "service.yaml"))
	Expect(err).NotTo(HaveOccurred())
	sources := map[model.SourceKey][]byte{}
	for _, name := range []string{"platform", "orchestration"} {
		contents, err := os.ReadFile(filepath.Join(directory, name+".yaml"))
		Expect(err).NotTo(HaveOccurred())
		sources[model.SourceKey{Namespace: "authz-system", Name: name}] = contents
	}
	return service, sources
}

func compileHierarchy(service []byte, sources map[model.SourceKey][]byte) model.PreparedRevision {
	GinkgoHelper()
	var serviceObject api.AuthorizationService
	Expect(yaml.UnmarshalStrict(service, &serviceObject)).To(Succeed())
	config, errs := validation.DecodeService(&serviceObject)
	Expect(errs).To(BeEmpty())
	observations := make(map[model.SourceKey]model.SourceObservation, len(sources))
	for key, contents := range sources {
		instance := model.SourceInstance{Key: key, UID: "hierarchy-" + key.Name, Origin: "hierarchy:" + key.Name}
		observation := model.SourceObservation{Instance: instance, Complete: true, Documents: map[model.Reference]model.DocumentState{}}
		for _, document := range splitDocuments(contents) {
			var object unstructured.Unstructured
			Expect(yaml.Unmarshal(document, &object)).To(Succeed())
			state := validation.DecodeDocument(instance, &object)
			Expect(state.Document).NotTo(BeNil(), "%v: %v", state.Key, state.Issues)
			observation.Documents[state.Key.Reference()] = state
		}
		observations[key] = observation
	}
	program, err := engine.Prepare(model.ServiceUID(serviceObject.UID), config, observations)
	Expect(err).NotTo(HaveOccurred())
	return program.Compilation.Prepared
}

func splitDocuments(contents []byte) [][]byte {
	GinkgoHelper()
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(contents)))
	var documents [][]byte
	for {
		document, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		Expect(err).NotTo(HaveOccurred())
		if len(bytes.TrimSpace(document)) != 0 {
			documents = append(documents, document)
		}
	}
	Expect(documents).NotTo(BeEmpty())
	return documents
}
