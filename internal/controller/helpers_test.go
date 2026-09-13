package controller

import (
	"context"
	"crypto/x509"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/resources"
	"github.com/zcayou/k8s-authz/internal/source"
	"github.com/zcayou/k8s-authz/internal/source/storage"
	"github.com/zcayou/k8s-authz/test/utils"
)

// startedRegistry returns a registry that runs until the spec ends.
func startedRegistry() *source.Registry {
	GinkgoHelper()
	registry := source.NewRegistry()
	stop := utils.Start(registry)
	DeferCleanup(func() { Expect(stop()).To(Succeed()) })
	return registry
}

func newPolicySourceSupervisor(controlClient client.Client, registry *source.Registry) *PolicySourceSupervisor {
	return &PolicySourceSupervisor{
		Client:      controlClient,
		APIReader:   controlClient,
		Registry:    registry,
		LocalConfig: &rest.Config{Host: "https://control.example.test:6443"},
	}
}

func newPolicySourceReconciler(controlClient client.Client, registry *source.Registry) *PolicySourceReconciler {
	return &PolicySourceReconciler{Client: client.WithFieldOwner(controlClient, resources.FieldOwner), Cache: controlClient, Registry: registry}
}

func newPolicySourceFakeClient(objects ...client.Object) client.WithWatch {
	return fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(objects...).
		WithStatusSubresource(&api.PolicySource{}).
		WithIndex(&api.PolicySource{}, policySourceKubeconfigIndex, policySourceSecretNames).
		Build()
}

// newServiceReconciler returns a reconciler over control whose writes carry
// the operator's field owner, as the manager's client's do, and whose events go
// to a buffered fake recorder.
func newServiceReconciler(control client.Client) *AuthorizationServiceReconciler {
	return &AuthorizationServiceReconciler{Client: client.WithFieldOwner(control, resources.FieldOwner), Clock: clock.RealClock{}, Recorder: events.NewFakeRecorder(64)}
}

func localPolicySource(name string, uid types.UID) *api.PolicySource {
	return &api.PolicySource{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: uid, Generation: 3},
		Spec: api.PolicySourceSpec{
			Provider:   api.PolicySourceProvider{Type: "Kubernetes"},
			Collection: []api.KeyRange{{Kinds: []string{model.KindPolicy}, Namespaces: []string{"policies"}, Names: []string{"*"}}},
		},
	}
}

func remotePolicySource(name string, uid types.UID, secretName string) *api.PolicySource {
	object := localPolicySource(name, uid)
	object.Spec.Provider.Kubernetes = &api.KubernetesProvider{Kubeconfig: &api.KubeconfigReference{
		SecretRef: api.SecretKeyRef{Name: secretName, Key: "kubeconfig"},
	}}
	return object
}

// remoteOrigin is the API server testKubeconfig reaches.
const remoteOrigin = "https://remote.example.test:6443"

func testKubeconfig(token string) []byte {
	return fmt.Appendf(nil, `apiVersion: v1
kind: Config
current-context: source
clusters:
- name: source
  cluster:
    server: %s
users:
- name: source
  user:
    token: %s
contexts:
- name: source
  context:
    cluster: source
    user: source
`, remoteOrigin, token)
}

// sourceInstance returns the instance of object's documents read from
// remoteOrigin.
func sourceInstance(object client.Object) model.SourceInstance {
	return model.SourceInstance{Key: sourceKeyOf(object), UID: string(object.GetUID()), Origin: remoteOrigin}
}

func sourceKeyOf(object client.Object) model.SourceKey {
	return model.SourceKey{Namespace: object.GetNamespace(), Name: object.GetName()}
}

// policyDocument returns an acquired Policy in instance.
func policyDocument(instance model.SourceInstance, name string) model.DocumentState {
	GinkgoHelper()
	state, err := utils.AcquiredDocument(instance, utils.Document(model.KindPolicy, "policies", name, `{"include":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"],"namespaces":["*"]}]}`))
	Expect(err).NotTo(HaveOccurred())
	return state
}

func completeView(instance model.SourceInstance, names ...string) model.SourceObservation {
	GinkgoHelper()
	view := model.SourceObservation{Instance: instance, Complete: true, Documents: map[model.Reference]model.DocumentState{}}
	for _, name := range names {
		state := policyDocument(instance, name)
		view.Documents[state.Key.Reference()] = state
	}
	return view
}

// cacheView writes view to the persistent cache of owner.
func cacheView(ctx context.Context, controlClient client.Client, owner *api.PolicySource, view model.SourceObservation) {
	GinkgoHelper()
	Expect(storage.Write(ctx, client.WithFieldOwner(controlClient, resources.FieldOwner), controlClient, owner, view)).To(Succeed())
}

// runReader registers object in registry with a fake reader and returns
// the reader and its emit function once it runs.
func runReader(registry *source.Registry, object *api.PolicySource) (*utils.FakeReader, func(model.SourceObservation)) {
	GinkgoHelper()
	reader := utils.NewFakeReader(nil)
	registration := source.Registration{Instance: sourceInstance(object), Digest: "fake", Settings: sourceSettings(object.Spec)}
	Expect(registry.Apply(registration, func() (source.Reader, error) { return reader, nil })).To(Succeed())
	var emit func(model.SourceObservation)
	Eventually(reader.Emitters()).Should(Receive(&emit))
	return reader, emit
}

func policySourceRequestFor(object client.Object) reconcile.Request {
	return reconcile.Request{NamespacedName: client.ObjectKeyFromObject(object)}
}

func observedPolicySourceStatus(
	ctx context.Context,
	controlClient client.Client,
	object client.Object,
) api.PolicySourceStatus {
	observed := &api.PolicySource{}
	Expect(controlClient.Get(ctx, client.ObjectKeyFromObject(object), observed)).To(Succeed())
	return observed.Status
}

// poolOf returns a pool holding authority's certificate.
func poolOf(authority utils.Material) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(authority.Certificate)
	return pool
}
