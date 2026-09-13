package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/engineclient"
	"github.com/zcayou/k8s-authz/internal/resources"
)

// route is the snapshot export's path pattern; SnapshotPath builds it.
const route = "GET /v1/namespaces/{namespace}/authorizationservices/{name}/pods/{pod}/snapshot"

// SnapshotPath is the path of the export of the snapshot installed on pod,
// an engine pod of the AuthorizationService name in namespace.
func SnapshotPath(namespace, name, pod string) string {
	return "/v1/namespaces/" + url.PathEscape(namespace) + "/authorizationservices/" + url.PathEscape(name) + "/pods/" + url.PathEscape(pod) + "/snapshot"
}

// Engines reads what an engine pod serves.
type Engines interface {
	// Installed returns the revision and conditions module digest target
	// serves.
	Installed(context.Context, engineclient.Target) (engineclient.Installed, error)
	// Snapshot returns the state document target serves, or nil when it has
	// none.
	Snapshot(context.Context, engineclient.Target) (json.RawMessage, error)
}

// Backend resolves a request's engine pod and reads its state.
type Backend struct {
	// Reader reads AuthorizationServices and engine Pods from the cache.
	Reader client.Reader
	// Namespaces are the namespaces the operator manages. Empty means all.
	Namespaces []string
	// Target addresses pod's management API, verified as service's engine.
	Target  func(ctx context.Context, service *api.AuthorizationService, pod *corev1.Pod) (engineclient.Target, error)
	Engines Engines
}

// export is the response: the state document the engine pod serves, relayed
// as it encoded it, the digest of the conditions module it serves, read
// before the state, and when they were read. State is null when the pod has
// none.
type export struct {
	ExportedAt       time.Time       `json:"exportedAt"`
	ConditionsDigest string          `json:"conditionsDigest"`
	State            json.RawMessage `json:"state"`
}

// NewHandler serves the snapshot export to callers that authenticate
// and are authorized to get the service's diagnostics subresource. It logs
// to log.
func NewHandler(log logr.Logger, authentication authenticator.Request, authorization authorizer.Authorizer, backend Backend) http.Handler {
	h := &handler{log: log, authentication: authentication, authorization: authorization, backend: backend}
	mux := http.NewServeMux()
	mux.HandleFunc(route, h.serve)
	return mux
}

type handler struct {
	log            logr.Logger
	authentication authenticator.Request
	authorization  authorizer.Authorizer
	backend        Backend
}

func (h *handler) serve(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	key := types.NamespacedName{Namespace: request.PathValue("namespace"), Name: request.PathValue("name")}
	if !h.authorize(writer, request, key) {
		return
	}
	ctx := request.Context()
	log := h.log.WithValues("authorizationService", key, "pod", request.PathValue("pod"))
	service, pod, err := h.engine(ctx, key, request.PathValue("pod"))
	switch {
	case apierrors.IsNotFound(err):
		http.Error(writer, err.Error(), http.StatusNotFound)
		return
	case err != nil:
		log.Error(err, "Could not read engine Pod")
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	case pod.Status.PodIP == "":
		http.Error(writer, "engine Pod has no IP", http.StatusServiceUnavailable)
		return
	}
	target, err := h.backend.Target(ctx, service, pod)
	if err != nil {
		log.Error(err, "Could not address engine Pod")
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	installed, err := h.backend.Engines.Installed(ctx, target)
	if err != nil {
		log.Error(err, "Could not read engine conditions module")
		http.Error(writer, err.Error(), http.StatusBadGateway)
		return
	}
	state, err := h.backend.Engines.Snapshot(ctx, target)
	if err != nil {
		log.Error(err, "Could not read engine state")
		http.Error(writer, err.Error(), http.StatusBadGateway)
		return
	}
	data, err := json.Marshal(export{ExportedAt: time.Now().UTC(), ConditionsDigest: installed.ConditionsDigest, State: state})
	if err != nil {
		log.Error(err, "Could not encode snapshot export")
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write(data)
}

// authorize authenticates request and authorizes get on the diagnostics
// subresource of the AuthorizationService key, as controller-runtime's metrics
// filter does for its path. It answers a request it refuses.
func (h *handler) authorize(writer http.ResponseWriter, request *http.Request, key types.NamespacedName) bool {
	// The delegating authenticator reports an invalid token as an error, so
	// errors are unauthorized, as kube-apiserver's authentication filter treats
	// them.
	response, authenticated, err := h.authentication.AuthenticateRequest(request)
	if err != nil || !authenticated {
		if err != nil {
			h.log.Error(err, "Could not authenticate request")
		}
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return false
	}
	user := response.User.GetName()
	decision, reason, err := h.authorization.Authorize(request.Context(), authorizer.AttributesRecord{
		User: response.User, Verb: "get", Namespace: key.Namespace, Name: key.Name,
		APIGroup: api.GroupVersion.Group, APIVersion: api.GroupVersion.Version, Resource: "authorizationservices", Subresource: "diagnostics",
		ResourceRequest: true,
	})
	if err != nil {
		h.log.Error(err, "Could not authorize request", "user", user)
		http.Error(writer, fmt.Sprintf("Authorization for user %s failed", user), http.StatusInternalServerError)
		return false
	}
	if decision != authorizer.DecisionAllow {
		h.log.V(4).Info("Denied request", "user", user, "reason", reason)
		http.Error(writer, fmt.Sprintf("Authorization denied for user %s", user), http.StatusForbidden)
		return false
	}
	return true
}

// engine reads the AuthorizationService key and its engine pod podName from
// the cache. A pod that isn't one of the service's engine pods, and a service
// outside the managed namespaces, are not found.
func (h *handler) engine(ctx context.Context, key types.NamespacedName, podName string) (*api.AuthorizationService, *corev1.Pod, error) {
	if len(h.backend.Namespaces) != 0 && !slices.Contains(h.backend.Namespaces, key.Namespace) {
		return nil, nil, apierrors.NewNotFound(api.GroupVersion.WithResource("authorizationservices").GroupResource(), key.Name)
	}
	service := &api.AuthorizationService{}
	if err := h.backend.Reader.Get(ctx, key, service); err != nil {
		return nil, nil, err
	}
	pod := &corev1.Pod{}
	if err := h.backend.Reader.Get(ctx, types.NamespacedName{Namespace: key.Namespace, Name: podName}, pod); err != nil {
		return nil, nil, err
	}
	if pod.Labels[resources.LabelServiceUID] != string(service.UID) {
		return nil, nil, apierrors.NewNotFound(corev1.Resource("pods"), podName)
	}
	return service, pod, nil
}
