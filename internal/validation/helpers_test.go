package validation_test

import (
	"encoding/json"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/validation"
	"github.com/zcayou/k8s-authz/test/utils"
)

var tenantSource = model.SourceInstance{Key: model.SourceKey{Namespace: "control", Name: "tenant-source"}, UID: "source-uid", Origin: "https://source.example"}

func customDocument(kind, name, spec string) *unstructured.Unstructured {
	return utils.Document(kind, "tenant", name, spec)
}

func nativeDocument(kind, name, body string) *unstructured.Unstructured {
	return utils.NativeDocument(kind, "tenant", name, body)
}

// policyInclude decodes a Policy whose only include rule is rule, and returns
// the cubes the rule normalizes to or the Policy's issue.
func policyInclude(rule api.OperationRule) ([]model.Cube, error) {
	GinkgoHelper()
	spec, err := json.Marshal(api.PolicySpec{Include: []api.OperationRule{rule}})
	Expect(err).NotTo(HaveOccurred())
	state := validation.DecodeDocument(tenantSource, customDocument(model.KindPolicy, "rule", string(spec)))
	if state.Document == nil {
		return nil, errors.New(issueMessage(state))
	}
	return state.Document.Policy.Include, nil
}

// bindingPrincipal decodes a PolicyBinding that selects subjects or match,
// and returns the principal it normalizes to or the binding's issue.
func bindingPrincipal(subjects []api.Subject, match *api.SubjectMatch) (model.Matcher, error) {
	GinkgoHelper()
	spec, err := json.Marshal(api.PolicyBindingSpec{PolicyRef: api.PolicyRef{Name: "policy"}, Subjects: subjects, SubjectMatch: match})
	Expect(err).NotTo(HaveOccurred())
	state := validation.DecodeDocument(tenantSource, customDocument(model.KindPolicyBinding, "binding", string(spec)))
	if state.Document == nil {
		return model.Matcher{}, errors.New(issueMessage(state))
	}
	return state.Document.Binding.Principal, nil
}

func issueMessage(state model.DocumentState) string {
	if len(state.Issues) == 0 {
		return ""
	}
	return state.Issues[0].Message
}

func authorizationService(spec api.AuthorizationServiceSpec) *api.AuthorizationService {
	return &api.AuthorizationService{ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: "authz"}, Spec: spec}
}

func validServiceSpec() api.AuthorizationServiceSpec {
	return api.AuthorizationServiceSpec{
		Program: api.AuthorizationProgram{Type: "Kubernetes"},
		Runtime: api.AuthorizationServiceRuntime{Type: api.RuntimeTypeDeployment, Deployment: &api.DeploymentRuntime{Replicas: 2}, MinReadyReplicas: 1},
		TLS: api.AuthorizationServiceTLS{
			Server: api.ServerTLS{
				SecretRef: api.SecretReference{Name: "server-tls"},
				CARef:     api.CABundleRef{ConfigMapKeyRef: &api.ConfigMapKeyRef{Name: "serving-ca", Key: "ca.crt"}},
			},
			Client: api.ClientTLS{CARef: api.CABundleRef{SecretKeyRef: &api.SecretKeyRef{Name: "client-ca", Key: "ca.crt"}}},
		},
		Endpoints: []api.Endpoint{{
			Name:       "fleet",
			Callers:    []api.Caller{{CommonName: "kube-apiserver"}},
			SourceRefs: []api.SourceRef{{Namespace: "control", Name: "platform"}}, Authorities: []api.Authority{},
			WhenEvaluationFails: api.DecisionFallbackDeny,
		}},
	}
}

func authority(source string, fallback api.DecisionFallback) api.Authority {
	return api.Authority{
		BindingRef:         api.BindingRef{Name: "root", Namespace: "platform", SourceRef: &api.SourceRef{Namespace: "control", Name: source}},
		WhenNoPolicyAllows: fallback,
	}
}
