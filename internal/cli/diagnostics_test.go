package cli_test

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/zcayou/k8s-authz/internal/diagnostics"
	"github.com/zcayou/k8s-authz/internal/resources"
)

const (
	operatorNamespace = "k8s-authz-system"
	operatorPod       = "k8s-authz-controller-manager-0"
	callerToken       = "caller-token"
)

var _ = Describe("Connected explain", func() {
	var (
		mutex    sync.Mutex
		requests []*http.Request
		refusal  int
		encoded  []byte
	)
	BeforeEach(func() {
		mutex.Lock()
		requests, refusal = nil, 0
		mutex.Unlock()
		encoded = export(time.Unix(2_000_000_000, 0), new(explanationFixture("empty")))
	})
	endpoint := func() string {
		return newDiagnosticsServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			mutex.Lock()
			requests = append(requests, request)
			status := refusal
			mutex.Unlock()
			if status != 0 {
				http.Error(writer, "access denied: no rule", status)
				return
			}
			_, _ = writer.Write(encoded)
		})).Listener.Addr().String()
	}
	pod := func(namespace, name string, labels map[string]string, ready bool) *corev1.Pod {
		status := corev1.ConditionFalse
		if ready {
			status = corev1.ConditionTrue
		}
		return &corev1.Pod{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "manager", Ports: []corev1.ContainerPort{{Name: "diagnostics", ContainerPort: 9443}}}}},
			Status:     corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: status}}},
		}
	}
	cluster := func() []runtime.Object {
		engineLabels := resources.ServiceEngineSelector("authz")
		return []runtime.Object{
			pod("control", "engine-a", engineLabels, false),
			pod("control", "engine-b", engineLabels, true),
			pod("control", "engine-foreign", resources.ServiceEngineSelector("other"), true),
			pod(operatorNamespace, "k8s-authz-controller-manager-not-ready", map[string]string{"authorization.zctx.io/component": "operator"}, false),
			pod(operatorNamespace, operatorPod, map[string]string{"authorization.zctx.io/component": "operator"}, true),
		}
	}
	explain := func(ctx SpecContext, api *fakeAPIServer, arguments ...string) (int, []byte, string) {
		directory := GinkgoT().TempDir()
		arguments = append([]string{"explain", "authz", "-n", "control", "--endpoint", "fleet", "--sar", writeReview(directory), "--kubeconfig", api.kubeconfig(directory, callerToken), "-o", "json"}, arguments...)
		return execute(ctx, "", arguments...)
	}

	It("reads the named pod through a port-forward to a ready operator pod with the caller's credentials, falling back from the websocket tunnel to SPDY", func(ctx SpecContext) {
		api := newFakeAPIServer(endpoint(), cluster()...)
		code, stdout, stderr := explain(ctx, api, "--pod", "engine-one")
		Expect(code).To(Equal(0), stderr)
		var report explanationReport
		Expect(json.Unmarshal(stdout, &report)).To(Succeed())
		Expect(report.Result).NotTo(BeEmpty())
		forwards, tokens := api.observed()
		Expect(forwards).To(Equal([]string{"GET " + operatorNamespace + "/" + operatorPod, "POST " + operatorNamespace + "/" + operatorPod}))
		Expect(tokens).To(HaveEach("Bearer " + callerToken))
		mutex.Lock()
		defer mutex.Unlock()
		Expect(requests).To(ConsistOf(And(
			HaveField("URL.Path", diagnostics.SnapshotPath("control", "authz", "engine-one")),
			HaveField("Header", HaveKeyWithValue("Authorization", ConsistOf("Bearer "+callerToken))),
		)))
	})

	It("reaches the forwarded diagnostics endpoint directly when the kubeconfig names a proxy", func(ctx SpecContext) {
		api := newFakeAPIServer(endpoint(), cluster()...)
		api.proxy = newConnectProxy(api.server.Listener.Addr().String())
		code, _, stderr := explain(ctx, api, "--pod", "engine-one")
		Expect(code).To(Equal(0), stderr)
	})

	It("reads a ready engine pod of the service when no pod is named", func(ctx SpecContext) {
		api := newFakeAPIServer(endpoint(), cluster()...)
		code, _, stderr := explain(ctx, api)
		Expect(code).To(Equal(0), stderr)
		mutex.Lock()
		defer mutex.Unlock()
		Expect(requests).To(ConsistOf(HaveField("URL.Path", diagnostics.SnapshotPath("control", "authz", "engine-b"))))
	})

	It("reports the endpoint's refusal", func(ctx SpecContext) {
		api := newFakeAPIServer(endpoint(), cluster()...)
		mutex.Lock()
		refusal = http.StatusForbidden
		mutex.Unlock()
		code, stdout, stderr := explain(ctx, api, "--pod", "engine-one")
		Expect(code).To(Equal(2))
		Expect(stdout).To(BeEmpty())
		Expect(stderr).To(ContainSubstring("diagnostics returned HTTP 403: access denied: no rule"))
	})

	It("reports an engine pod without installed policy", func(ctx SpecContext) {
		encoded = export(time.Unix(2_000_000_000, 0), nil)
		api := newFakeAPIServer(endpoint(), cluster()...)
		code, stdout, stderr := explain(ctx, api, "--pod", "engine-one")
		Expect(code).To(Equal(2))
		Expect(stdout).To(BeEmpty())
		Expect(stderr).To(ContainSubstring("engine pod has no installed policy"))
	})

	It("fails without a ready operator pod", func(ctx SpecContext) {
		api := newFakeAPIServer(endpoint(), cluster()...)
		code, _, stderr := explain(ctx, api, "--pod", "engine-one", "--operator-namespace", "elsewhere")
		Expect(code).To(Equal(2))
		Expect(stderr).To(ContainSubstring("select an operator pod in namespace elsewhere: no ready Pod"))
		forwards, _ := api.observed()
		Expect(forwards).To(BeEmpty())
	})
})
