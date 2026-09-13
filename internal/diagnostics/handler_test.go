package diagnostics_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/diagnostics"
	"github.com/zcayou/k8s-authz/internal/engineclient"
	"github.com/zcayou/k8s-authz/internal/resources"
	"github.com/zcayou/k8s-authz/test/utils"
)

const (
	installedState   = `{"revision":"sha256:installed","serviceUID":"service"}`
	controlNamespace = "control"
	enginePod        = "engine"
	engineAddress    = "10.0.0.1"
	validToken       = "valid"
)

var _ = Describe("Snapshot export", func() {
	var (
		handler    http.Handler
		attributes []authorizer.Attributes
		engines    *utils.FakeEngines
	)
	BeforeEach(func() {
		service := utils.AuthorizationService(types.NamespacedName{Namespace: controlNamespace, Name: "authz"})
		other := utils.AuthorizationService(types.NamespacedName{Namespace: controlNamespace, Name: "other"})
		other.UID = "other-uid"
		pod := func(name string, owner *api.AuthorizationService) *corev1.Pod {
			return &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: controlNamespace, Name: name, Labels: map[string]string{resources.LabelServiceUID: string(owner.UID)}},
				Status:     corev1.PodStatus{PodIP: engineAddress},
			}
		}
		scheme, err := utils.Scheme()
		Expect(err).NotTo(HaveOccurred())
		unaddressed := pod("unaddressed", service)
		unaddressed.Status.PodIP = ""
		reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(service, other, pod(enginePod, service), pod("foreign", other), unaddressed).Build()
		engines = utils.NewFakeEngines()
		engines.Install(engineAddress, []byte(installedState))
		engines.InstallModule(engineAddress, "sha256:module")
		attributes = nil
		authentication := authenticator.RequestFunc(func(request *http.Request) (*authenticator.Response, bool, error) {
			if request.Header.Get("Authorization") != "Bearer "+validToken {
				return nil, false, nil
			}
			return &authenticator.Response{User: &user.DefaultInfo{Name: "reader", Groups: []string{user.AllAuthenticated}}}, true, nil
		})
		authorization := authorizer.AuthorizerFunc(func(_ context.Context, record authorizer.Attributes) (authorizer.Decision, string, error) {
			attributes = append(attributes, record)
			switch record.GetName() {
			case "denied":
				return authorizer.DecisionNoOpinion, "no rule", nil
			case "failing":
				return authorizer.DecisionNoOpinion, "", errors.New("SubjectAccessReview failed")
			}
			return authorizer.DecisionAllow, "", nil
		})
		handler = diagnostics.NewHandler(GinkgoLogr, authentication, authorization, diagnostics.Backend{
			Reader: reader, Namespaces: []string{controlNamespace}, Engines: engines,
			Target: func(_ context.Context, service *api.AuthorizationService, pod *corev1.Pod) (engineclient.Target, error) {
				return engineclient.Target{Address: pod.Status.PodIP, ServerName: service.Name}, nil
			},
		})
	})
	get := func(namespace, service, pod string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, diagnostics.SnapshotPath(namespace, service, pod), nil)
		request.Header.Set("Authorization", "Bearer "+validToken)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	It("relays the state of the service's engine pod to an authorized caller", func() {
		before := time.Now()
		response := get(controlNamespace, "authz", enginePod)
		Expect(response.Code).To(Equal(http.StatusOK), response.Body.String())
		Expect(response.Header().Get("Cache-Control")).To(Equal("no-store"))
		Expect(response.Header().Get("Content-Type")).To(Equal("application/json"))
		var relayed struct {
			ExportedAt       time.Time       `json:"exportedAt"`
			ConditionsDigest string          `json:"conditionsDigest"`
			State            json.RawMessage `json:"state"`
		}
		Expect(json.Unmarshal(response.Body.Bytes(), &relayed)).To(Succeed())
		Expect(relayed.ExportedAt).To(BeTemporally(">=", before))
		Expect(relayed.ConditionsDigest).To(Equal("sha256:module"))
		Expect(relayed.State).To(MatchJSON(installedState))
		Expect(engines.Targets()).To(HaveEach(engineclient.Target{Address: engineAddress, ServerName: "authz"}))
	})

	It("relays null state for an engine pod without any", func() {
		engines.Install(engineAddress, nil)
		response := get(controlNamespace, "authz", enginePod)
		Expect(response.Code).To(Equal(http.StatusOK), response.Body.String())
		var relayed map[string]any
		Expect(json.Unmarshal(response.Body.Bytes(), &relayed)).To(Succeed())
		Expect(relayed).To(HaveKeyWithValue("state", BeNil()))
	})

	It("authorizes get on the named service's diagnostics subresource", func() {
		get(controlNamespace, "authz", enginePod)
		Expect(attributes).To(ConsistOf(authorizer.AttributesRecord{
			User: &user.DefaultInfo{Name: "reader", Groups: []string{user.AllAuthenticated}}, Verb: "get", Namespace: controlNamespace, Name: "authz",
			APIGroup: api.GroupVersion.Group, APIVersion: api.GroupVersion.Version, Resource: "authorizationservices", Subresource: "diagnostics", ResourceRequest: true,
		}))
	})

	It("rejects an unauthenticated caller before authorizing", func() {
		request := httptest.NewRequest(http.MethodGet, diagnostics.SnapshotPath(controlNamespace, "authz", enginePod), nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		Expect(response.Code).To(Equal(http.StatusUnauthorized))
		Expect(attributes).To(BeEmpty())
		Expect(engines.Targets()).To(BeEmpty())
	})

	It("forbids a caller the authorizer doesn't allow", func() {
		response := get(controlNamespace, "denied", enginePod)
		Expect(response.Code).To(Equal(http.StatusForbidden))
		Expect(engines.Targets()).To(BeEmpty())
	})

	It("reports a failed authorization as an internal error", func() {
		response := get(controlNamespace, "failing", enginePod)
		Expect(response.Code).To(Equal(http.StatusInternalServerError))
		Expect(response.Body.String()).NotTo(ContainSubstring("SubjectAccessReview failed"))
		Expect(engines.Targets()).To(BeEmpty())
	})

	DescribeTable("reports what isn't one of the service's engine pods as not found",
		func(namespace, service, pod string) {
			response := get(namespace, service, pod)
			Expect(response.Code).To(Equal(http.StatusNotFound), response.Body.String())
			Expect(engines.Targets()).To(BeEmpty())
		},
		Entry("another service's pod", controlNamespace, "authz", "foreign"),
		Entry("a missing pod", controlNamespace, "authz", "missing"),
		Entry("a missing service", controlNamespace, "missing", enginePod),
		Entry("an unmanaged namespace", "elsewhere", "authz", enginePod),
	)

	It("reports a failed engine read as a bad gateway", func() {
		engines.Fail(engineAddress, errors.New("connection refused"))
		response := get(controlNamespace, "authz", enginePod)
		Expect(response.Code).To(Equal(http.StatusBadGateway))
		Expect(response.Body.String()).To(ContainSubstring("connection refused"))
	})

	It("reports a failed conditions module read as a bad gateway without reading the state", func() {
		engines.Fail(engineAddress, errors.New("connection refused"))
		response := get(controlNamespace, "authz", enginePod)
		Expect(response.Code).To(Equal(http.StatusBadGateway))
		Expect(engines.Targets()).To(HaveLen(1))
	})

	It("reports an engine pod without an IP as unavailable", func() {
		Expect(get(controlNamespace, "authz", "unaddressed").Code).To(Equal(http.StatusServiceUnavailable))
		Expect(engines.Targets()).To(BeEmpty())
	})
})
