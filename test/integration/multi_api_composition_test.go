//go:build integration

package integration

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("multi-API policy composition", func() {
	It("compiles a restricted remote native RoleBinding through the production reconcilers", func(ctx SpecContext) {
		remoteConfig, err := remoteAPI()
		Expect(err).NotTo(HaveOccurred())

		remoteControl, err := client.New(remoteConfig, client.Options{Scheme: k8sClient.Scheme()})
		Expect(err).NotTo(HaveOccurred())
		remoteClientset, err := kubernetes.NewForConfig(remoteConfig)
		Expect(err).NotTo(HaveOccurred())
		installRemotePolicyGraph(ctx, remoteControl)
		kubeconfig := installRemoteSourceCredential(ctx, remoteConfig, remoteClientset)

		controlNamespace := newNamespace(ctx, "multi-api-control")
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: controlNamespace, Name: "remote"},
			Data:       map[string][]byte{"kubeconfig": kubeconfig},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		policySource := multiAPIPolicySource(controlNamespace)
		Expect(createAndRemove(ctx, policySource)).To(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policySource), policySource)).To(Succeed())
			g.Expect(apimeta.FindStatusCondition(policySource.Status.Conditions, api.ConditionSynchronized)).To(HaveField("Status", metav1.ConditionTrue))
			g.Expect(policySource.Status.LastAdmittedTime).NotTo(BeNil())
			g.Expect(policySource.Status.Issues).To(BeEmpty())
		}).WithTimeout(convergence).Should(Succeed())

		service := createService(ctx, controlNamespace, func(service *api.AuthorizationService) {
			service.Spec.Endpoints[0].SourceRefs = []api.SourceRef{{Namespace: policySource.Namespace, Name: policySource.Name}}
			service.Spec.Endpoints[0].Authorities = []api.Authority{{
				BindingRef: api.BindingRef{
					Name: "entry", Namespace: "remote-policy",
					SourceRef: &api.SourceRef{Namespace: policySource.Namespace, Name: policySource.Name},
				},
				WhenNoPolicyAllows: "Deny",
			}}
		})
		installTLS(ctx, service)
		pod := createEnginePod(ctx, controlNamespace, "remote-engine", podAddress(5), deployment(ctx, service).Spec.Template, true)
		var content model.ContentRevision
		Eventually(func(g Gomega) {
			content = pushed(g, pod)
			g.Expect(content.Revision).NotTo(BeEmpty())
			var current api.AuthorizationService
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(service), &current)).To(Succeed())
			g.Expect(current.Status.DesiredRevision).To(Equal(string(content.Revision)))
			g.Expect(apimeta.FindStatusCondition(current.Status.Conditions, api.ConditionPrepared)).To(HaveField("Status", metav1.ConditionTrue))
			g.Expect(current.Status.Issues).NotTo(ContainElement(HaveField("Reason", string(model.ReasonSourceUnavailable))))
		}).WithTimeout(convergence).Should(Succeed())
		assertRemoteDocumentPaths(content, model.SourceKey{Namespace: policySource.Namespace, Name: policySource.Name})
		assertRemoteNativeDecision(ctx, content)
	}, SpecTimeout(time.Minute))
})

func multiAPIPolicySource(namespace string) *api.PolicySource {
	return &api.PolicySource{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "remote"},
		Spec: api.PolicySourceSpec{
			Provider: api.PolicySourceProvider{Type: "Kubernetes", Kubernetes: &api.KubernetesProvider{
				Kubeconfig: &api.KubeconfigReference{SecretRef: api.SecretKeyRef{Name: "remote", Key: "kubeconfig"}},
			}},
			Collection: []api.KeyRange{
				{Kinds: []string{model.KindPolicyBinding}, Namespaces: []string{"remote-policy"}, Names: []string{"entry"}},
				{Kinds: []string{model.KindPolicySet}, Namespaces: []string{"remote-policy"}, Names: []string{"tenant-root"}},
				{Kinds: []string{model.KindRole}, Namespaces: []string{"remote-policy"}, Names: []string{"viewer"}},
				{Kinds: []string{model.KindRoleBinding}, Namespaces: []string{"remote-policy"}, Names: []string{"viewer-binding"}},
			},
		},
	}
}

func installRemotePolicyGraph(ctx context.Context, control client.Client) {
	GinkgoHelper()
	Expect(control.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "remote-policy"}})).To(Succeed())
	Expect(control.Create(ctx, &api.PolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: "remote-policy", Name: "entry"},
		Spec:       api.PolicyBindingSpec{SubjectMatch: &api.SubjectMatch{}, PolicyRef: api.PolicyRef{Kind: model.KindPolicySet, Name: "tenant-root"}},
	})).To(Succeed())

	Expect(control.Create(ctx, &api.PolicySet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "remote-policy", Name: "tenant-root"},
		Spec: api.PolicySetSpec{BindingRefs: []api.BindingRef{{
			APIGroup: rbacv1.GroupName, Kind: model.KindRoleBinding,
			Namespace: "remote-policy", Name: "viewer-binding",
		}}},
	})).To(Succeed())
	Expect(control.Create(ctx, &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: "remote-policy", Name: "viewer"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
	})).To(Succeed())
	Expect(control.Create(ctx, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: "remote-policy", Name: "viewer-binding"},
		Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: "team:viewers"}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: model.KindRole, Name: "viewer"},
	})).To(Succeed())
}

func installRemoteSourceCredential(ctx context.Context, remoteConfig *rest.Config, admin kubernetes.Interface) []byte {
	GinkgoHelper()
	const accountName = "policy-reader"
	account, err := admin.CoreV1().ServiceAccounts("remote-policy").Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Namespace: "remote-policy", Name: accountName},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	_, err = admin.RbacV1().Roles("remote-policy").Create(ctx, &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: "remote-policy", Name: "policy-source-reader"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{api.GroupVersion.Group}, Resources: []string{"policysets", "policybindings"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{rbacv1.GroupName}, Resources: []string{"roles", "rolebindings"}, Verbs: []string{"get", "list", "watch"}},
		},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	_, err = admin.RbacV1().RoleBindings("remote-policy").Create(ctx, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: "remote-policy", Name: "policy-source-reader"},
		Subjects: []rbacv1.Subject{{
			Kind: rbacv1.ServiceAccountKind, Namespace: account.Namespace, Name: account.Name,
		}},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: model.KindRole, Name: "policy-source-reader"},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	_, err = admin.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "policy-source-schema-reader"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"apiextensions.k8s.io"}, Resources: []string{"customresourcedefinitions"},
			ResourceNames: []string{"policysets." + api.GroupVersion.Group, "policybindings." + api.GroupVersion.Group}, Verbs: []string{"get", "watch"},
		}},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	_, err = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "policy-source-schema-reader"},
		Subjects: []rbacv1.Subject{{
			Kind: rbacv1.ServiceAccountKind, Namespace: account.Namespace, Name: account.Name,
		}},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "policy-source-schema-reader"},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	kubeconfig, err := utils.ServiceAccountKubeconfig(ctx, remoteConfig, types.NamespacedName{Namespace: account.Namespace, Name: account.Name}, remoteConfig.Host)
	Expect(err).NotTo(HaveOccurred())
	return kubeconfig
}

// assertRemoteDocumentPaths checks that the contributions attribute their
// paths to every remote document of the graph.
func assertRemoteDocumentPaths(content model.ContentRevision, source model.SourceKey) {
	GinkgoHelper()
	found := map[string]bool{}
	for _, contribution := range content.Contributions {
		for _, key := range contribution.Path {
			if key.Source.Key == source {
				found[key.Kind+"/"+key.Name] = true
			}
		}
	}
	Expect(found).To(Equal(map[string]bool{
		model.KindPolicyBinding + "/entry":             true,
		model.KindPolicySet + "/" + "tenant-root":      true,
		model.KindRole + "/" + "viewer":                true,
		model.KindRoleBinding + "/" + "viewer-binding": true,
	}))
}

func assertRemoteNativeDecision(ctx context.Context, content model.ContentRevision) {
	GinkgoHelper()
	evaluate := func(namespace string) model.Decision {
		review := authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{APIVersion: authorizationv1.SchemeGroupVersion.String(), Kind: "SubjectAccessReview"},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				Groups:             []string{"team:viewers"},
				ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: "get", Namespace: namespace, Version: "v1", Resource: "pods", Name: "pod-a"},
			},
		}
		evaluation, err := utils.Evaluate(ctx, content.PreparedRevision, utils.EndpointName, review)
		Expect(err).NotTo(HaveOccurred())
		return evaluation.Decision
	}
	Expect(evaluate("remote-policy")).To(And(HaveField("Result", model.Result("Allow")), HaveField("Reason", "Allowed")))
	Expect(evaluate("other-tenant")).To(And(HaveField("Result", model.Result("Deny")), HaveField("Reason", "NoPolicyAllows")))
}
