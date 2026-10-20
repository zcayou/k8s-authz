//go:build integration

package integration

import (
	"context"
	"encoding/pem"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/controller"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/source"
	kubernetessource "github.com/zcayou/k8s-authz/internal/source/kubernetes"
	"github.com/zcayou/k8s-authz/internal/source/storage"
	"github.com/zcayou/k8s-authz/test/utils"
)

var policyGVR = schema.GroupVersionResource{Group: api.GroupVersion.Group, Version: "v1alpha1", Resource: "policies"}

// workloadsPolicy returns the Policy workloads, which allows getting pods
// in every namespace.
func workloadsPolicy(namespace string) *unstructured.Unstructured {
	return utils.Document(model.KindPolicy, namespace, "workloads", `{"include":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"],"namespaces":["*"]}]}`)
}

func policySpec(verb string) map[string]any {
	return map[string]any{"include": []any{map[string]any{
		"apiGroups": []any{""}, "resources": []any{"pods"}, "verbs": []any{verb}, "namespaces": []any{"*"},
	}}}
}

// runReader runs reader until the spec ends, delivering every observation
// it emits.
func runReader(ctx context.Context, reader *kubernetessource.Reader) <-chan model.SourceObservation {
	observations := make(chan model.SourceObservation, 8)
	running, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader.Run(running, func(value model.SourceObservation) {
			select {
			case observations <- value:
			case <-running.Done():
			}
		})
	}()
	DeferCleanup(func() {
		cancel()
		Eventually(done).WithTimeout(convergence).Should(BeClosed())
	})
	return observations
}

// receiveComplete waits for a complete observation whose documents match
// documents, dropping the observations before it.
func receiveComplete(observations <-chan model.SourceObservation, documents gomegatypes.GomegaMatcher) model.SourceObservation {
	GinkgoHelper()
	var value model.SourceObservation
	Eventually(observations).WithTimeout(convergence).Should(Receive(&value, And(HaveField("Complete", BeTrue()), HaveField("Documents", documents))))
	return value
}

// newReader returns a reader that reaches the API server through configuration.
func newReader(configuration *rest.Config, instance model.SourceInstance, collection kubernetessource.Collection) *kubernetessource.Reader {
	GinkgoHelper()
	documents, err := dynamic.NewForConfig(configuration)
	Expect(err).NotTo(HaveOccurred())
	return kubernetessource.NewReader(documents, instance, collection)
}

// startRegistry runs a registry until the spec ends with a reader of collection
// applied for instance, which reaches the API server through configuration.
func startRegistry(configuration *rest.Config, instance model.SourceInstance, collection kubernetessource.Collection) *source.Registry {
	GinkgoHelper()
	registry := source.NewRegistry()
	reader := newReader(configuration, instance, collection)
	Expect(registry.Apply(source.Registration{Instance: instance, Coverage: collection, Digest: "reader"}, func() (source.Reader, error) {
		return reader, nil
	})).To(Succeed())
	stop := utils.Start(registry)
	DeferCleanup(func() { Expect(stop()).To(Succeed()) })
	return registry
}

// synchronizedView waits for a complete acquisition and returns the view.
func synchronizedView(registry *source.Registry, key model.SourceKey) model.SourceObservation {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		health := registry.Health(key)
		g.Expect(health.Complete).To(BeTrue(), fmt.Sprintf("health=%#v", health))
	}, 10*time.Second).Should(Succeed())
	return registry.Effective(key)
}

// expectRetainedFailure waits for health with reason and a message containing
// message, then asserts the registry still serves initial.
func expectRetainedFailure(registry *source.Registry, initial model.SourceObservation, reason, message string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		health := registry.Health(initial.Instance.Key)
		g.Expect(health.Complete).To(BeFalse())
		g.Expect(health.Reason).To(Equal(reason))
		g.Expect(health.Message).To(ContainSubstring(message))
	}, 10*time.Second).Should(Succeed())
	effective := registry.Snapshot()[initial.Instance.Key]
	Expect(effective.Complete).To(BeTrue())
	Expect(effective.Documents).To(Equal(initial.Documents))
}

// apiProxy forwards requests to the API server configuration reaches unless
// intercept reports that it answered the request itself.
func apiProxy(configuration *rest.Config, intercept func(http.ResponseWriter, *http.Request) bool) *httptest.Server {
	GinkgoHelper()
	upstream, err := url.Parse(configuration.Host)
	Expect(err).NotTo(HaveOccurred())
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport, err = rest.TransportFor(configuration)
	Expect(err).NotTo(HaveOccurred())
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !intercept(writer, request) {
			proxy.ServeHTTP(writer, request)
		}
	}))
	DeferCleanup(func() {
		server.CloseClientConnections()
		server.Close()
	})
	return server
}

// newDynamicClient returns a dynamic client for the suite's API server.
func newDynamicClient() dynamic.Interface {
	GinkgoHelper()
	documents, err := dynamic.NewForConfig(cfg)
	Expect(err).NotTo(HaveOccurred())
	return documents
}

// sourceFixture is a remote PolicySource whose kubeconfig Secret holds
// a ServiceAccount token that can read the Policies in its namespace.
type sourceFixture struct {
	namespace string
	account   types.NamespacedName
	secret    *corev1.Secret
	object    *api.PolicySource
}

func newSourceFixture(ctx context.Context, policies ...string) *sourceFixture {
	GinkgoHelper()
	namespace := newNamespace(ctx, "policy-source")
	for _, name := range policies {
		Expect(k8sClient.Create(ctx, &api.Policy{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec:       api.PolicySpec{Include: []api.OperationRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}, Namespaces: []string{"*"}}}},
		})).To(Succeed())
	}
	account, _ := grantReader(ctx, namespace)
	return registerSource(ctx, namespace, account, api.PolicySourceSpec{
		Collection: []api.KeyRange{{Kinds: []string{model.KindPolicy}, Namespaces: []string{namespace}, Names: []string{"*"}}},
	})
}

// newSelectionFixture is a remote source that collects the documents
// and the labels of a namespace labeled owner=infra. Its PolicyBinding entry
// targets the PolicySet root, whose binding applications selects the PolicySets
// labeled entry=application in namespaces labeled owner=infra. The PolicySet
// access is so labeled, and grants every principal get on pods.
func newSelectionFixture(ctx context.Context) *sourceFixture {
	GinkgoHelper()
	namespace := newNamespace(ctx, "selection-source")
	labelNamespace(ctx, namespace, map[string]string{"owner": "infra"})
	createSelectionDocuments(ctx, namespace)
	account, _ := grantReader(ctx, namespace)
	grantSelectionReader(ctx, account)
	return registerSource(ctx, namespace, account, api.PolicySourceSpec{
		Collection:      []api.KeyRange{{Kinds: []string{model.KindPolicy, model.KindPolicyBinding, model.KindPolicySet}, Namespaces: []string{namespace}, Names: []string{"*"}}},
		NamespaceLabels: api.NamespaceLabelsCollect,
	})
}

// createSelectionDocuments creates newSelectionFixture's documents
// in namespace.
func createSelectionDocuments(ctx context.Context, namespace string) {
	GinkgoHelper()
	all := &api.SubjectMatch{}
	for _, object := range []client.Object{
		&api.PolicyBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "entry"}, Spec: api.PolicyBindingSpec{SubjectMatch: all, PolicyRef: &api.PolicyRef{Kind: model.KindPolicySet, Name: "root"}}},
		&api.PolicySet{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "root"}, Spec: api.PolicySetSpec{BindingRefs: []api.BindingRef{{Name: "applications"}}}},
		&api.PolicyBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "applications"}, Spec: api.PolicyBindingSpec{SubjectMatch: all, PolicySelector: &api.PolicySelector{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"owner": "infra"}},
			Selector:          metav1.LabelSelector{MatchLabels: map[string]string{"entry": "application"}},
		}}},
		&api.PolicySet{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "access", Labels: map[string]string{"entry": "application"}}, Spec: api.PolicySetSpec{BindingRefs: []api.BindingRef{{Name: "grant"}}}},
		&api.PolicyBinding{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "grant"}, Spec: api.PolicyBindingSpec{SubjectMatch: all, PolicyRef: &api.PolicyRef{Name: "pods"}}},
		&api.Policy{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "pods"}, Spec: api.PolicySpec{Include: []api.OperationRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}, Namespaces: []string{"*"}}}}},
	} {
		Expect(k8sClient.Create(ctx, object)).To(Succeed())
	}
}

// labelNamespace replaces namespace's labels, other than the one the API
// server sets, with labels.
func labelNamespace(ctx context.Context, namespace string, labels map[string]string) {
	GinkgoHelper()
	Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var object corev1.Namespace
		if err := k8sClient.Get(ctx, client.ObjectKey{Name: namespace}, &object); err != nil {
			return err
		}
		object.Labels = maps.Clone(labels)
		if object.Labels == nil {
			object.Labels = map[string]string{}
		}
		object.Labels[corev1.LabelMetadataName] = namespace
		return k8sClient.Update(ctx, &object)
	})).To(Succeed())
}

// selection is the selection newSelectionFixture's binding applications
// makes in the source key.
func selection(key model.SourceKey) model.Selection {
	return model.Selection{
		Source:     key,
		Namespaces: model.LabelSelector{{Key: "owner", Operator: metav1.LabelSelectorOpIn, Values: []string{"infra"}}},
		Sets:       model.LabelSelector{{Key: "entry", Operator: metav1.LabelSelectorOpIn, Values: []string{"application"}}},
	}
}

// registerSource creates a PolicySource in namespace with spec's collection
// and settings, which reads its API with a token for account.
func registerSource(ctx context.Context, namespace string, account types.NamespacedName, spec api.PolicySourceSpec) *sourceFixture {
	GinkgoHelper()
	fixture := &sourceFixture{namespace: namespace, account: account}
	fixture.secret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "reader-kubeconfig"},
		Data:       map[string][]byte{"kubeconfig": fixture.kubeconfig(ctx)},
	}
	Expect(k8sClient.Create(ctx, fixture.secret)).To(Succeed())
	spec.Provider = api.PolicySourceProvider{Type: "Kubernetes", Kubernetes: &api.KubernetesProvider{
		Kubeconfig: &api.KubeconfigReference{SecretRef: api.SecretKeyRef{Name: fixture.secret.Name, Key: "kubeconfig"}},
	}}
	fixture.object = &api.PolicySource{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "remote"}, Spec: spec}
	Expect(createAndRemove(ctx, fixture.object)).To(Succeed())
	return fixture
}

// grantSelectionReader lets account also list and watch the PolicyBindings
// and PolicySets in its namespace, and that namespace itself, by name, until
// the spec ends.
func grantSelectionReader(ctx context.Context, account types.NamespacedName) {
	GinkgoHelper()
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: account.Namespace + "-selection-reader"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{api.GroupVersion.Group}, Resources: []string{"policybindings", "policysets"}, Verbs: []string{"list", "watch"}},
			{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{account.Namespace}, Verbs: []string{"list", "watch"}},
		},
	}
	Expect(createAndRemove(ctx, role)).To(Succeed())
	Expect(createAndRemove(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: role.Name},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: account.Namespace, Name: account.Name}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name},
	})).To(Succeed())
}

// grantReader creates a ServiceAccount in namespace that can list and watch
// Policies and read the product CRDs until the spec ends, and returns
// it with the binding that grants it.
func grantReader(ctx context.Context, namespace string) (types.NamespacedName, *rbacv1.ClusterRoleBinding) {
	GinkgoHelper()
	account := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "reader"}}
	Expect(k8sClient.Create(ctx, account)).To(Succeed())
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: namespace + "-reader"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{api.GroupVersion.Group}, Resources: []string{"policies"}, Verbs: []string{"list", "watch"}},
			{APIGroups: []string{"apiextensions.k8s.io"}, Resources: []string{"customresourcedefinitions"}, Verbs: []string{"get", "list", "watch"}},
		},
	}
	Expect(createAndRemove(ctx, role)).To(Succeed())
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: role.Name},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: account.Namespace, Name: account.Name}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name},
	}
	Expect(createAndRemove(ctx, binding)).To(Succeed())
	return client.ObjectKeyFromObject(account), binding
}

func (f *sourceFixture) kubeconfig(ctx context.Context) []byte {
	GinkgoHelper()
	kubeconfig, err := utils.ServiceAccountKubeconfig(ctx, cfg, f.account, cfg.Host)
	Expect(err).NotTo(HaveOccurred())
	return kubeconfig
}

func (f *sourceFixture) key() model.SourceKey {
	return model.SourceKey{Namespace: f.object.Namespace, Name: f.object.Name}
}

func (f *sourceFixture) instance() model.SourceInstance {
	GinkgoHelper()
	origin, err := kubernetessource.Origin(cfg)
	Expect(err).NotTo(HaveOccurred())
	return model.SourceInstance{Key: f.key(), UID: string(f.object.UID), Origin: origin}
}

// cachedNamespaceLabels returns whether the source's persistent cache
// collects namespace labels, and the labels it holds.
func (f *sourceFixture) cachedNamespaceLabels(ctx context.Context) (bool, map[string]map[string]string) {
	GinkgoHelper()
	view, _, err := storage.Read(ctx, k8sClient, f.instance())
	Expect(err).NotTo(HaveOccurred())
	return view.CollectsNamespaceLabels, view.NamespaceLabels
}

// cached returns the names of the documents in the source's persistent cache.
func (f *sourceFixture) cached(ctx context.Context) []string {
	GinkgoHelper()
	view, _, err := storage.Read(ctx, k8sClient, f.instance())
	Expect(err).NotTo(HaveOccurred())
	names := make([]string, 0, len(view.Documents))
	for reference := range view.Documents {
		names = append(names, reference.Name)
	}
	return names
}

// cacheLabels selects the source's persistent cache Secrets.
func (f *sourceFixture) cacheLabels() client.MatchingLabels {
	return client.MatchingLabels{"authorization.zctx.io/source": f.object.Name}
}

// synchronized waits for the operator to report a complete acquisition
// of the current spec.
func (f *sourceFixture) synchronized(ctx context.Context) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(f.object), f.object)).To(Succeed())
		g.Expect(f.object.Status.ObservedGeneration).To(Equal(f.object.Generation))
		g.Expect(apimeta.FindStatusCondition(f.object.Status.Conditions, api.ConditionSynchronized)).To(HaveField("Status", metav1.ConditionTrue))
	}).WithTimeout(convergence).Should(Succeed())
}

// cachedEventually waits for the source's persistent cache to hold the named
// documents.
func (f *sourceFixture) cachedEventually(ctx context.Context, names ...string) {
	GinkgoHelper()
	Eventually(func() []string { return f.cached(ctx) }).WithTimeout(convergence).Should(ConsistOf(names))
}

func (f *sourceFixture) condition(ctx context.Context) *metav1.Condition {
	GinkgoHelper()
	Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(f.object), f.object)).To(Succeed())
	return apimeta.FindStatusCondition(f.object.Status.Conditions, api.ConditionSynchronized)
}

// update changes the source's spec with mutate and waits for the operator
// to observe it.
func (f *sourceFixture) update(ctx context.Context, mutate func(*api.PolicySourceSpec)) {
	GinkgoHelper()
	Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(f.object), f.object); err != nil {
			return err
		}
		mutate(&f.object.Spec)
		return k8sClient.Update(ctx, f.object)
	})).To(Succeed())
	Eventually(func(g Gomega) {
		g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(f.object), f.object)).To(Succeed())
		g.Expect(f.object.Status.ObservedGeneration).To(Equal(f.object.Generation))
	}).WithTimeout(convergence).Should(Succeed())
}

// expectRegisteredOnlyWithView fails the spec if registry ever reports
// the source registered under its UID without its documents.
func (f *sourceFixture) expectRegisteredOnlyWithView(registry *source.Registry) {
	var bare atomic.Bool
	registry.Subscribe(func(key model.SourceKey) {
		if uid, _ := registry.Registered(key); key == f.key() && uid == string(f.object.UID) && len(registry.Snapshot()[key].Documents) == 0 {
			bare.Store(true)
		}
	})
	DeferCleanup(func() { Expect(bare.Load()).To(BeFalse(), "the source was registered without its view") })
}

// expectRestored asserts that registry holds the source under its UID with its
// cached documents, and that its health has reason.
func (f *sourceFixture) expectRestored(registry *source.Registry, reason string) {
	GinkgoHelper()
	uid, registered := registry.Registered(f.key())
	Expect(registered).To(BeTrue())
	Expect(uid).To(Equal(string(f.object.UID)))
	view := registry.Snapshot()[f.key()]
	Expect(view.Complete).To(BeTrue())
	Expect(view.Instance).To(Equal(f.instance()))
	Expect(view.Documents).To(ConsistOf(HaveField("Key.Name", "workloads")))
	Expect(registry.Health(f.key()).Reason).To(Equal(reason))
}

// replica is the source registry and supervisor of an operator replica that has
// just started.
type replica struct {
	registry   *source.Registry
	supervisor *controller.PolicySourceSupervisor
}

// startReplica starts a replica, reading Secrets through secrets, that runs
// until the spec ends.
func startReplica(secrets client.Reader) replica {
	GinkgoHelper()
	registry := source.NewRegistry()
	stop := utils.Start(registry)
	DeferCleanup(func() { Expect(stop()).To(Succeed()) })
	return replica{registry: registry, supervisor: &controller.PolicySourceSupervisor{Client: k8sClient, APIReader: secrets, Registry: registry, LocalConfig: cfg}}
}

// reconcile registers the fixture's source on the replica.
func (r replica) reconcile(ctx context.Context, fixture *sourceFixture) {
	GinkgoHelper()
	_, err := r.supervisor.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(fixture.object)})
	Expect(err).NotTo(HaveOccurred())
}

// policyRegistration returns a source instance and a collection of the named
// Policies in namespace.
func policyRegistration(name, namespace, objectName string) (model.SourceInstance, kubernetessource.Collection) {
	instance := model.SourceInstance{Key: model.SourceKey{Namespace: "system", Name: name}, UID: "uid-" + name, Origin: "https://test-origin"}
	return instance, kubernetessource.Collection{Ranges: []api.KeyRange{{Kinds: []string{model.KindPolicy}, Namespaces: []string{namespace}, Names: []string{objectName}}}}
}

// proxyConfig reaches server, trusting only its certificate. The proxy
// authenticates the requests it forwards.
func proxyConfig(server *httptest.Server) *rest.Config {
	return &rest.Config{
		Host:            server.URL,
		TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})},
	}
}
