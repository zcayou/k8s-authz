package validation_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/validation"
)

var _ = Describe("Principal normalization", func() {
	It("resolves native subjects to the users and groups they match", func() {
		matcher, err := bindingPrincipal([]api.Subject{
			{Kind: "User", Name: "alice"},
			{Kind: model.KindGroup, APIGroup: rbacv1.GroupName, Name: "operators"},
			{Kind: "ServiceAccount", Namespace: "elastic-system", Name: "controller"},
		}, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(matcher.Kind).To(Equal(model.MatcherSubjects))
		Expect(matcher.Subjects).To(ConsistOf(
			model.PrincipalSubject{Kind: model.KindUser, Name: "alice"},
			model.PrincipalSubject{Kind: model.KindGroup, Name: "operators"},
			model.PrincipalSubject{Kind: model.KindUser, Name: "system:serviceaccount:elastic-system:controller"},
		))
	})
	It("keeps each requirement and sorts its operands", func() {
		matcher, err := bindingPrincipal(nil, &api.SubjectMatch{Requirements: []api.SubjectRequirement{
			{Kind: "User", Operator: "StartsWith", Names: []string{"oidc:"}},
			{Kind: model.KindGroup, Operator: "In", Names: []string{"production-approved", "engineering"}},
			{Kind: "Extra", Key: "scope", Operator: "In", Values: []string{"read", "prod"}},
		}})
		Expect(err).NotTo(HaveOccurred())
		Expect(matcher.Kind).To(Equal(model.MatcherRequirements))
		Expect(matcher.Requirements).To(ConsistOf(
			model.SubjectRequirement{Kind: model.KindUser, Operator: "StartsWith", Values: []string{"oidc:"}},
			model.SubjectRequirement{Kind: model.KindGroup, Operator: model.OperatorIn, Values: []string{"engineering", "production-approved"}},
			model.SubjectRequirement{Kind: "Extra", Key: "scope", Operator: model.OperatorIn, Values: []string{"prod", "read"}},
		))
	})
	DescribeTable("rejects subjects that would not resolve to one principal", func(subjects []api.Subject, fragment string) {
		_, err := bindingPrincipal(subjects, nil)
		Expect(err).To(MatchError(ContainSubstring(fragment)))
	},
		Entry("service account without namespace", []api.Subject{{Kind: "ServiceAccount", Name: "controller"}}, "invalid namespace"),
		Entry("service account name with a colon", []api.Subject{{Kind: "ServiceAccount", Namespace: "default", Name: "a:b"}}, "invalid name"),
	)
	It("distinguishes an empty subjectMatch, which matches everyone, from a native binding without subjects", func() {
		all, err := bindingPrincipal(nil, &api.SubjectMatch{})
		Expect(err).NotTo(HaveOccurred())
		Expect(all).To(Equal(model.AllPrincipals()))
		state := validation.DecodeDocument(tenantSource, nativeDocument(model.KindRoleBinding, "unbound", `{"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"}}`))
		Expect(state.Document).NotTo(BeNil(), issueMessage(state))
		Expect(state.Document.Binding.Principal).To(Equal(model.Matcher{Kind: model.MatcherSubjects}))
	})
})
