//go:build integration

package integration

import (
	"net/http"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	kubernetessource "github.com/zcayou/k8s-authz/internal/source/kubernetes"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("Reader", func() {
	var client dynamic.Interface
	BeforeEach(func() {
		client = newDynamicClient()
	})

	It("publishes initialized caches and semantic document updates", func(ctx SpecContext) {
		namespace := newNamespace(ctx, "reader-watch")
		created, err := client.Resource(policyGVR).Namespace(namespace).Create(ctx, workloadsPolicy(namespace), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		instance, collection := policyRegistration(namespace, namespace, "workloads")
		observations := runReader(ctx, newReader(cfg, instance, collection))

		initial := receiveComplete(observations, And(HaveLen(1), HaveEach(HaveField("Document", Not(BeNil())))))

		created.SetAnnotations(map[string]string{"note": "metadata-only"})
		created, err = client.Resource(policyGVR).Namespace(namespace).Update(ctx, created, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())
		metadataOnly := receiveComplete(observations, HaveEach(WithTransform(objectRevision, Equal(created.GetResourceVersion()))))
		for reference, document := range metadataOnly.Documents {
			Expect(document.Digest).To(Equal(initial.Documents[reference].Digest))
		}

		created.Object["spec"] = policySpec("list")
		created, err = client.Resource(policyGVR).Namespace(namespace).Update(ctx, created, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())
		updated := receiveComplete(observations, HaveEach(WithTransform(objectRevision, Equal(created.GetResourceVersion()))))
		for reference, document := range updated.Documents {
			Expect(document.Digest).NotTo(Equal(initial.Documents[reference].Digest))
		}

		Expect(client.Resource(policyGVR).Namespace(namespace).Delete(ctx, created.GetName(), metav1.DeleteOptions{})).To(Succeed())
		receiveComplete(observations, BeEmpty())
	}, NodeTimeout(30*time.Second))

	It("reports WatchFailing and retains its admitted view across API disconnection", func(ctx SpecContext) {
		namespace := newNamespace(ctx, "reader-reconnect")
		var offline atomic.Bool
		server := apiProxy(cfg, func(writer http.ResponseWriter, _ *http.Request) bool {
			if !offline.Load() {
				return false
			}
			http.Error(writer, "API unavailable", http.StatusServiceUnavailable)
			return true
		})
		instance, collection := policyRegistration("reconnect", namespace, "workloads")
		registry := startRegistry(instance, newReader(proxyConfig(server), instance, collection))
		initial := synchronizedView(registry, instance.Key)
		Expect(initial.Documents).To(BeEmpty())

		offline.Store(true)
		server.CloseClientConnections()
		_, err := client.Resource(policyGVR).Namespace(namespace).Create(ctx, workloadsPolicy(namespace), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		expectRetainedFailure(registry, initial, api.ReasonWatchFailing, "")

		offline.Store(false)
		Eventually(func(g Gomega) {
			g.Expect(synchronizedView(registry, instance.Key).Documents).To(HaveLen(1))
		}, 15*time.Second).Should(Succeed())
	}, NodeTimeout(30*time.Second))

	It("reports WatchFailing and retains its admitted view when its credential loses access after the initial sync", func(ctx SpecContext) {
		namespace := newNamespace(ctx, "reader-forbidden")
		_, err := client.Resource(policyGVR).Namespace(namespace).Create(ctx, workloadsPolicy(namespace), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		account, binding := grantReader(ctx, namespace)
		kubeconfig, err := utils.ServiceAccountKubeconfig(ctx, cfg, account, cfg.Host)
		Expect(err).NotTo(HaveOccurred())
		credential, err := kubernetessource.ParseKubeconfig(kubeconfig)
		Expect(err).NotTo(HaveOccurred())
		server := apiProxy(credential, func(http.ResponseWriter, *http.Request) bool { return false })
		instance, collection := policyRegistration("forbidden", namespace, "workloads")
		registry := startRegistry(instance, newReader(proxyConfig(server), instance, collection))
		initial := synchronizedView(registry, instance.Key)
		Expect(initial.Documents).To(HaveLen(1))

		Expect(k8sClient.Delete(ctx, binding)).To(Succeed())
		documents, err := dynamic.NewForConfig(credential)
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() error {
			_, err := documents.Resource(policyGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
			return err
		}).WithTimeout(convergence).Should(MatchError(apierrors.IsForbidden, "IsForbidden"))
		// The established watches outlive the revocation until they're reestablished.
		server.CloseClientConnections()
		expectRetainedFailure(registry, initial, api.ReasonWatchFailing, "forbidden")
	}, NodeTimeout(30*time.Second))

	It("clears WatchFailing when an empty collection lists successfully again", func(ctx SpecContext) {
		namespace := newNamespace(ctx, "reader-empty-recovery")
		var offline atomic.Bool
		server := apiProxy(cfg, func(writer http.ResponseWriter, _ *http.Request) bool {
			if !offline.Load() {
				return false
			}
			http.Error(writer, "API unavailable", http.StatusServiceUnavailable)
			return true
		})
		instance, collection := policyRegistration("empty-recovery", namespace, "*")
		registry := startRegistry(instance, newReader(proxyConfig(server), instance, collection))
		initial := synchronizedView(registry, instance.Key)
		Expect(initial.Documents).To(BeEmpty())

		offline.Store(true)
		server.CloseClientConnections()
		expectRetainedFailure(registry, initial, api.ReasonWatchFailing, "")

		// Nothing changes in the collection, so no informer event follows
		// the recovery; only the successful list or watch clears the failure.
		offline.Store(false)
		Expect(synchronizedView(registry, instance.Key).Documents).To(BeEmpty())
	}, NodeTimeout(30*time.Second))
})

// objectRevision is the resourceVersion of the object a document was decoded
// from.
func objectRevision(state model.DocumentState) (string, error) {
	object := &unstructured.Unstructured{}
	if err := object.UnmarshalJSON(state.Object); err != nil {
		return "", err
	}
	return object.GetResourceVersion(), nil
}
