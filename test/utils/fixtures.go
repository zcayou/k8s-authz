package utils

import (
	"encoding/json"
	"fmt"

	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/compiler"
	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/validation"
)

// The names AuthorizationService refers to.
const (
	ServiceUID       = "service-uid"
	ServerTLSSecret  = "server-tls"
	ServingCASecret  = "serving-ca"
	ClientCASecret   = "client-ca"
	CAKey            = "ca.crt"
	CallerCommonName = "kube-apiserver"
	EndpointName     = "fleet"
	SourceName       = "local"
)

// AuthorizationService returns a service of runtime kind Deployment at key
// with one endpoint that reads the SourceName PolicySource in the same
// namespace.
func AuthorizationService(key types.NamespacedName) *api.AuthorizationService {
	return &api.AuthorizationService{
		TypeMeta:   metav1.TypeMeta{APIVersion: api.GroupVersion.String(), Kind: "AuthorizationService"},
		ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name, UID: ServiceUID, Generation: 1},
		Spec: api.AuthorizationServiceSpec{
			Program: api.AuthorizationProgram{Type: "Kubernetes"},
			Runtime: api.AuthorizationServiceRuntime{Type: api.RuntimeTypeDeployment, Deployment: &api.DeploymentRuntime{Replicas: 2}, MinReadyReplicas: 1},
			TLS: api.AuthorizationServiceTLS{
				Server: api.ServerTLS{
					SecretRef: api.SecretReference{Name: ServerTLSSecret},
					CARef:     api.CABundleRef{SecretKeyRef: &api.SecretKeyRef{Name: ServingCASecret, Key: CAKey}},
				},
				Client: api.ClientTLS{CARef: api.CABundleRef{SecretKeyRef: &api.SecretKeyRef{Name: ClientCASecret, Key: CAKey}}},
			},
			Endpoints: []api.Endpoint{{
				Name: EndpointName, WhenEvaluationFails: api.DecisionFallbackDeny,
				Callers:    []api.Caller{{CommonName: CallerCommonName}},
				SourceRefs: []api.SourceRef{{Namespace: key.Namespace, Name: SourceName}}, Authorities: []api.Authority{},
			}},
		},
	}
}

// SubjectAccessReview returns a review of user's verb on a core v1 resource
// in namespace.
func SubjectAccessReview(user, verb, resource, namespace string) authorizationv1.SubjectAccessReview {
	return authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		Spec:     authorizationv1.SubjectAccessReviewSpec{User: user, ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: verb, Resource: resource, Version: "v1", Namespace: namespace}},
	}
}

// SecretProhibitionProgram compiles a program whose "cluster" endpoint allows
// the user admin everything except reading Secrets in kube-system.
func SecretProhibitionProgram() (model.PreparedRevision, error) {
	return compileProgram(nil, []programDocument{
		{model.KindPolicy, "all", `{"include":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}`},
		{model.KindPolicyBinding, "admin", `{"policyRef":{"name":"all"},"subjects":[{"kind":"User","name":"admin"}]}`},
		{model.KindPolicy, "secret-prohibition", `{"include":[{"apiGroups":[""],"resources":["secrets"],"verbs":["get","list","watch"],"namespaces":["kube-system"]}]}`},
		{model.KindPolicyBinding, "prohibit", `{"policyRef":{"name":"secret-prohibition"},"subjectMatch":{}}`},
		{model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"}],"prohibitionRefs":[{"name":"prohibit"}]}`},
	})
}

// ConditionalProgram compiles a program whose "cluster" endpoint allows
// the user admin to read Pods where the Rego condition whose rules are rules
// allows it. The source allows the default builtins.
func ConditionalProgram(rules string) (model.PreparedRevision, error) {
	rego, err := json.Marshal("package condition\n" + rules + "\n")
	if err != nil {
		return model.PreparedRevision{}, err
	}
	return compileProgram(new(condition.DefaultBuiltins()), []programDocument{
		{model.KindPolicy, "pods", `{"include":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}],"condition":{"rego":` + string(rego) + `}}`},
		{model.KindPolicyBinding, "admin", `{"policyRef":{"name":"pods"},"subjects":[{"kind":"User","name":"admin"}]}`},
		{model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"}]}`},
	})
}

type programDocument struct{ kind, name, spec string }

// compileProgram compiles documents, with the entry binding that targets
// the PolicySet root, as one source whose conditions may call allowed.
// Its "cluster" endpoint admits CallerCommonName.
func compileProgram(allowed *model.BuiltinSet, documents []programDocument) (model.PreparedRevision, error) {
	source := model.SourceInstance{Key: model.SourceKey{Namespace: "control", Name: SourceName}, UID: "source-1", Origin: "api-local"}
	observed := model.SourceObservation{Instance: source, Complete: true, Documents: map[model.Reference]model.DocumentState{}, AllowedBuiltins: allowed}
	documents = append(documents, programDocument{model.KindPolicyBinding, "entry", `{"policyRef":{"kind":"PolicySet","name":"root"},"subjectMatch":{}}`})
	for _, document := range documents {
		state := validation.DecodeDocument(source, Document(document.kind, "policies", document.name, document.spec))
		if state.Document == nil {
			return model.PreparedRevision{}, fmt.Errorf("%s/%s is invalid: %v", document.kind, document.name, state.Issues)
		}
		observed.Documents[state.Key.Reference()] = state
	}
	entry := model.Reference{Source: source.Key, Group: api.GroupVersion.Group, Kind: model.KindPolicyBinding, Namespace: "policies", Name: "entry"}
	config := model.ServiceConfig{Endpoints: []model.EndpointConfig{{
		Name: "cluster", WhenEvaluationFails: "Deny", Callers: []string{CallerCommonName},
		Sources: []model.SourceKey{source.Key}, Authorities: []model.AuthorityConfig{{Binding: entry, Fallback: "NoOpinion"}},
	}}}
	compilation, err := compiler.Compile(config, map[model.SourceKey]model.SourceObservation{source.Key: observed}, compiler.DefaultLimits())
	if err != nil {
		return model.PreparedRevision{}, err
	}
	return compilation.Prepared, nil
}

// Document returns a product document of kind whose spec is the JSON spec.
func Document(kind, namespace, name, spec string) *unstructured.Unstructured {
	return document(api.GroupVersion.WithKind(kind), namespace, name, `{"spec":`+spec+`}`)
}

// NativeDocument returns an RBAC document of kind whose top-level fields
// are the JSON object body.
func NativeDocument(kind, namespace, name, body string) *unstructured.Unstructured {
	return document(rbacv1.SchemeGroupVersion.WithKind(kind), namespace, name, body)
}

func document(gvk schema.GroupVersionKind, namespace, name, body string) *unstructured.Unstructured {
	result := &unstructured.Unstructured{}
	if err := json.Unmarshal([]byte(body), &result.Object); err != nil {
		panic(fmt.Sprintf("document %s %s/%s: %v", gvk.Kind, namespace, name, err))
	}
	result.SetGroupVersionKind(gvk)
	result.SetNamespace(namespace)
	result.SetName(name)
	result.SetUID(types.UID(name + "-uid"))
	return result
}

// AcquiredDocument decodes object as a document of source the way a reader
// acquires it, keeping its JSON as the state's Object.
func AcquiredDocument(source model.SourceInstance, object *unstructured.Unstructured) (model.DocumentState, error) {
	encoded, err := object.MarshalJSON()
	if err != nil {
		return model.DocumentState{}, fmt.Errorf("encode %s %s/%s: %w", object.GetKind(), object.GetNamespace(), object.GetName(), err)
	}
	state := validation.DecodeDocument(source, object)
	state.Object = encoded
	return state, nil
}
