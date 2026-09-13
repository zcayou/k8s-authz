//go:build integration

package integration

import (
	"context"
	"crypto/x509"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/resources"
	"github.com/zcayou/k8s-authz/test/utils"
)

const runtimeKindLabel = "authorization.zctx.io/runtime-kind"

// createService creates the fixture AuthorizationService in namespace
// and deletes it when the spec ends.
func createService(ctx context.Context, namespace string, edit func(*api.AuthorizationService)) *api.AuthorizationService {
	GinkgoHelper()
	service := utils.AuthorizationService(types.NamespacedName{Namespace: namespace, Name: "authz"})
	service.UID, service.Generation = "", 0
	if edit != nil {
		edit(service)
	}
	Expect(createAndRemove(ctx, service)).To(Succeed())
	return service
}

// updateService applies edit to the latest service, retrying when
// the operator's status writes conflict with it.
func updateService(ctx context.Context, service *api.AuthorizationService, edit func(*api.AuthorizationService)) {
	GinkgoHelper()
	Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(service), service); err != nil {
			return err
		}
		edit(service)
		return k8sClient.Update(ctx, service)
	})).To(Succeed())
}

// deployment waits for the service's Deployment.
func deployment(ctx context.Context, service *api.AuthorizationService) *appsv1.Deployment {
	GinkgoHelper()
	var result appsv1.Deployment
	Eventually(func() error {
		return k8sClient.Get(ctx, workloadKey(service), &result)
	}).WithTimeout(convergence).Should(Succeed())
	return &result
}

func workloadKey(service *api.AuthorizationService) types.NamespacedName {
	return types.NamespacedName{Namespace: service.Namespace, Name: resources.Name(service.Name)}
}

func engineConfigKey(service *api.AuthorizationService) types.NamespacedName {
	return types.NamespacedName{Namespace: service.Namespace, Name: resources.Name(service.Name) + "-engine"}
}

// installTLS creates the Secrets the service's TLS settings name: its
// client CA, its serving CA and a serving certificate that CA issued.
func installTLS(ctx context.Context, service *api.AuthorizationService) {
	GinkgoHelper()
	servingCA, clientCA := authority(), authority()
	server, err := servingCA.Issue("server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, resources.ServerName(service.Namespace, service.Name))
	Expect(err).NotTo(HaveOccurred())
	for name, bundle := range map[string][]byte{utils.ClientCASecret: clientCA.CertificatePEM, utils.ServingCASecret: servingCA.CertificatePEM} {
		Expect(k8sClient.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: service.Namespace, Name: name}, Data: map[string][]byte{utils.CAKey: bundle}})).To(Succeed())
	}
	Expect(k8sClient.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: service.Namespace, Name: utils.ServerTLSSecret}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{corev1.TLSCertKey: server.CertificatePEM, corev1.TLSPrivateKeyKey: server.KeyPEM}})).To(Succeed())
}

// createEnginePod stands in for the workload controller and the kubelet:
// it creates a pod from template and reports its engine started at address.
func createEnginePod(ctx context.Context, namespace, name, address string, template corev1.PodTemplateSpec, ready bool) *corev1.Pod {
	GinkgoHelper()
	pod := &corev1.Pod{ObjectMeta: *template.ObjectMeta.DeepCopy(), Spec: *template.Spec.DeepCopy()}
	pod.Namespace, pod.Name = namespace, name
	Expect(k8sClient.Create(ctx, pod)).To(Succeed())
	pod.Status = corev1.PodStatus{PodIP: address, Phase: corev1.PodPending, ContainerStatuses: []corev1.ContainerStatus{{Name: resources.ContainerName, Started: new(true)}}}
	if ready {
		pod.Status.Phase = corev1.PodRunning
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	}
	Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())
	return pod
}

// serviceStatus returns the service's current status.
func serviceStatus(ctx context.Context, g Gomega, service *api.AuthorizationService) api.AuthorizationServiceStatus {
	var current api.AuthorizationService
	g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(service), &current)).To(Succeed())
	return current.Status
}

// events returns the Events recorded in namespace.
func events(ctx context.Context, g Gomega, namespace string) []eventsv1.Event {
	var list eventsv1.EventList
	g.Expect(k8sClient.List(ctx, &list, client.InNamespace(namespace))).To(Succeed())
	return list.Items
}

// podAddress returns a distinct pod IP for index.
func podAddress(index int) string {
	return fmt.Sprintf("10.2.0.%d", index)
}
