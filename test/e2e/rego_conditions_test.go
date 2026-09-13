//go:build e2e

package e2e

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/model"
)

var _ = Describe("Rego conditions", Label("rego-conditions"), func() {
	const (
		namespacedUser = "oidc:ns-user"
		matchingGroup  = "oidc:ns-" + workloadNamespace
		otherGroup     = "oidc:ns-elsewhere"
	)

	// expectPodList waits until the API server lets namespacedUser in group list
	// pods when allowed, or refuses it otherwise.
	expectPodList := func(ctx context.Context, group string, allowed bool) {
		GinkgoHelper()
		Eventually(func(g Gomega) {
			output, err := listPods(ctx, namespacedUser, group)
			if allowed {
				g.Expect(err).NotTo(HaveOccurred())
				return
			}
			g.Expect(err).To(HaveOccurred())
			g.Expect(output).To(ContainSubstring("Forbidden"))
		}, 2*time.Minute).Should(Succeed())
	}
	expectIssue := func(ctx context.Context, reason model.IssueReason) {
		GinkgoHelper()
		Eventually(func(g Gomega) {
			g.Expect(authorizationService(ctx).Status.Issues).To(ContainElement(HaveField("Reason", string(reason))))
		}, 2*time.Minute).Should(Succeed())
	}

	BeforeEach(func(ctx SpecContext) {
		expectBaseline(ctx)
		for _, name := range []string{"local", "remote"} {
			Expect(patchSource(ctx, name, `{"spec":{"rego":{}}}`)).To(Succeed())
			DeferCleanup(func(ctx SpecContext) {
				Expect(patchSource(ctx, name, `{"spec":{"rego":null}}`)).To(Succeed())
			})
		}
		Expect(suite.member.apply(ctx, groupNamespaceDocuments)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			Expect(suite.member.kubectl(ctx, "-n", remotePolicyNamespace, "delete", "policy,policybinding", "group-namespaces",
				"--ignore-not-found")).Error().NotTo(HaveOccurred())
		})
		Expect(suite.member.kubectl(ctx, "-n", remotePolicyNamespace, "patch", "policyset", "team", "--type=merge", "-p",
			`{"spec":{"bindingRefs":[{"name":"admins"},{"name":"group-namespaces"}]}}`)).Error().NotTo(HaveOccurred())
		DeferCleanup(func(ctx SpecContext) {
			Expect(suite.member.kubectl(ctx, "-n", remotePolicyNamespace, "patch", "policyset", "team", "--type=merge", "-p",
				`{"spec":{"bindingRefs":[{"name":"admins"}]}}`)).Error().NotTo(HaveOccurred())
		})
		expectPodList(ctx, matchingGroup, true)
	})

	It("grants the namespace a group names and falls back elsewhere", func(ctx SpecContext) {
		expectPodList(ctx, matchingGroup, true)
		expectPodList(ctx, otherGroup, false)
	})

	It("stops the grant when a source on its path no longer allows Rego", func(ctx SpecContext) {
		Expect(patchSource(ctx, "local", `{"spec":{"rego":null}}`)).To(Succeed())
		expectIssue(ctx, model.ReasonRegoNotAllowed)
		expectPodList(ctx, matchingGroup, false)
	})

	It("refuses a builtin the service's ceiling doesn't allow", func(ctx SpecContext) {
		Expect(patchService(ctx, `{"spec":{"rego":{"allowedBuiltins":["startswith"]}}}`)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			Expect(patchService(ctx, `{"spec":{"rego":null}}`)).To(Succeed())
		})
		expectIssue(ctx, model.ReasonBuiltinNotAllowed)
		expectPodList(ctx, matchingGroup, false)
	})
})

// patchSource merge-patches the PolicySource name.
func patchSource(ctx context.Context, name, patch string) error {
	_, err := kubectl(ctx, "-n", controlNamespace, "patch", "policysource", name, "--type=merge", "-p", patch)
	return err
}

// groupNamespaceDocuments grant a group oidc:ns-NAME's members everything
// in the namespace NAME.
const groupNamespaceDocuments = `apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: e2e-remote
  name: group-namespaces
spec:
  condition:
    rego: |
      package condition

      allow if {
        some group in input.principal.groups
        namespace := trim_prefix(group, "oidc:ns-")
        namespace != group
        input.request.resourceAttributes.namespace == namespace
      }
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: e2e-remote
  name: group-namespaces
spec:
  subjectMatch:
    requirements:
      - kind: Group
        operator: StartsWith
        names: ["oidc:ns-"]
  policyRef:
    name: group-namespaces
`
