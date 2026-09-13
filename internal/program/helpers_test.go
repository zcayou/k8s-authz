package program_test

import (
	"context"
	"encoding/json"
	"maps"
	"math/rand/v2"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/open-policy-agent/opa/v1/rego"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/test/utils"
)

const (
	otherValue         = "other"
	apiName            = "api"
	appsNamespace      = "apps"
	deployments        = "deployments"
	developers         = "developers"
	metadataName       = "metadata.name"
	profileScope       = "profile"
	redTeam            = "red"
	teamLabel          = "team"
	requestSeedOne     = uint64(0x7c42_115e_d3a9_0381)
	requestSeedTwo     = uint64(0x1df8_b099_eb40_a727)
	generatedCases     = 256
	defaultNamespace   = "default"
	teamNamespace      = "team-a"
	authenticatedGroup = "system:authenticated"
	openidScope        = "openid"
	blueTeam           = "blue"
	systemNamespace    = "kube-system"
	listVerb           = "list"
	getVerb            = "get"
	podsResource       = "pods"
	aliceName          = "alice"
	secretsResource    = "secrets"
)

// normalizedRequest is kubernetes.normalize's result.
type normalizedRequest struct {
	Valid     bool            `json:"valid"`
	Error     string          `json:"error"`
	Principal model.Principal `json:"principal"`
	Query     normalizedQuery `json:"query"`
	// ConditionInput is the input Rego conditions read, as Rego encoded it.
	ConditionInput json.RawMessage `json:"conditionInput"`
}

type normalizedQuery struct {
	Regions map[string]model.Region `json:"regions"`
	// encoded holds the regions as Rego encoded them, before normalization.
	encoded map[string]model.Region
}

// normalizer evaluates the Kubernetes program's normalize on its input.
var normalizer = sync.OnceValues(func() (rego.PreparedEvalQuery, error) {
	modules := engine.Modules()
	options := make([]func(*rego.Rego), 0, len(modules)+1)
	options = append(options, rego.Query("data.authz.program.kubernetes.normalize(input)"))
	for name, text := range modules {
		options = append(options, rego.Module(name, text))
	}
	return rego.New(options...).PrepareForEval(context.Background())
})

// evaluate normalizes the raw review data. Its regions are in Go's normal
// form, so they compare equal to the model's constructors; the query keeps
// Rego's own encoding too.
func evaluate(ctx context.Context, data []byte) normalizedRequest {
	GinkgoHelper()
	prepared, err := normalizer()
	Expect(err).NotTo(HaveOccurred())
	var input any
	Expect(json.Unmarshal(data, &input)).To(Succeed())
	results, err := prepared.Eval(ctx, rego.EvalInput(input))
	Expect(err).NotTo(HaveOccurred())
	Expect(results).To(HaveLen(1))
	Expect(results[0].Expressions).To(HaveLen(1))
	encoded, err := json.Marshal(results[0].Expressions[0].Value)
	Expect(err).NotTo(HaveOccurred())
	var result normalizedRequest
	Expect(json.Unmarshal(encoded, &result)).To(Succeed())
	result.Query.encoded = maps.Clone(result.Query.Regions)
	for dimension, region := range result.Query.Regions {
		result.Query.Regions[dimension] = region.Normalize()
	}
	return result
}

// normalize normalizes a review normalization accepts.
func normalize(ctx context.Context, review authorizationv1.SubjectAccessReview) normalizedRequest {
	GinkgoHelper()
	request := evaluate(ctx, reviewJSON(review))
	Expect(request.Valid).To(BeTrue(), request.Error)
	return request
}

func baseReview() authorizationv1.SubjectAccessReview {
	return authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: aliceName, Groups: []string{authenticatedGroup, developers, developers}, UID: "uid-1",
			Extra: map[string]authorizationv1.ExtraValue{
				"scopes":        {profileScope, openidScope, profileScope},
				"present-empty": {},
			},
		},
		Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true, Reason: "caller supplied"},
	}
}

func resourceReview(attributes authorizationv1.ResourceAttributes) authorizationv1.SubjectAccessReview {
	review := baseReview()
	review.Spec.ResourceAttributes = &attributes
	return review
}

func expectSingle(query normalizedQuery, dimension, value string) {
	GinkgoHelper()
	Expect(query.Regions).To(HaveKeyWithValue(dimension, model.Values(value)))
}

func reviewJSON(review authorizationv1.SubjectAccessReview) []byte {
	GinkgoHelper()
	data, err := json.Marshal(review)
	Expect(err).NotTo(HaveOccurred())
	return data
}

func labelSelector(requirements []metav1.LabelSelectorRequirement) *authorizationv1.LabelSelectorAttributes {
	return &authorizationv1.LabelSelectorAttributes{Requirements: requirements}
}

func permuteStrings(random *rand.Rand, values []string) []string {
	result := make([]string, len(values))
	for position, index := range random.Perm(len(values)) {
		result[position] = values[index]
	}
	return result
}

func assertNamespaceFootprint(query normalizedQuery, namespace string, index int) {
	GinkgoHelper()
	if namespace == "" {
		expectSingle(query, model.IngressNamespace, model.Atom(""))
		Expect(query.Regions[model.AffectedNamespace].Contains(utils.NamespaceWitness)).To(BeTrue(), "case=%d", index)
		Expect(query.Regions[model.AffectedNamespace].Contains(model.Atom(defaultNamespace))).To(BeTrue(), "case=%d", index)
		return
	}
	expectSingle(query, model.IngressNamespace, model.Atom(namespace))
	expectSingle(query, model.AffectedNamespace, model.Atom(namespace))
}

// malformedReviews are requests normalization can't encode.
var malformedReviews = []string{
	`null`,
	`{"apiVersion":"authorization.k8s.io/v1beta1","kind":"SubjectAccessReview","spec":{"user":"alice","resourceAttributes":{"verb":"get","resource":"pods"}}}`,
	`{"apiVersion":"authorization.k8s.io/v1","kind":"Other","spec":{"user":"alice","resourceAttributes":{"verb":"get","resource":"pods"}}}`,
	`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":null}`,
	`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"alice"}}`,
	`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"alice","resourceAttributes":{"verb":"get","resource":"pods"},"nonResourceAttributes":{"verb":"get","path":"/healthz"}}}`,
	`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":1,"resourceAttributes":{"verb":"get","resource":"pods"}}}`,
	`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"alice","groups":"developers","resourceAttributes":{"verb":"get","resource":"pods"}}}`,
	`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"alice","resourceAttributes":"pods"}}`,
	`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"alice","resourceAttributes":{"verb":"get","resource":"pods\u0000"}}}`,
	`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"alice","resourceAttributes":{"verb":"get","resource":"pods","subresource":"\u0000log"}}}`,
	`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"alice","resourceAttributes":{"verb":"list","resource":"pods","fieldSelector":{"rawSelector":"metadata.name=api","requirements":[{"key":"metadata.name","operator":"In","values":["api"]}]}}}}`,
}

// openWorldReviews each normalize like the same request without their
// unread fields and explicit nulls.
var openWorldReviews = []string{
	`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","unknown":true,"spec":{"user":"alice","resourceAttributes":{"verb":"list","resource":"pods","namespace":"apps","labelSelector":{"requirements":[{"key":"team","operator":"In","values":["blue"]}]}}}}`,
	`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","metadata":{"name":1,"ownerReferences":[{"unknown":true}]},"status":{"allowed":"yes","unknown":true},"spec":{"user":"alice","resourceAttributes":{"verb":"list","resource":"pods","namespace":"apps","labelSelector":{"requirements":[{"key":"team","operator":"In","values":["blue"]}]}}}}`,
	`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"alice","future":{"shape":[1]},"resourceAttributes":{"verb":"list","resource":"pods","namespace":"apps","unknown":true,"labelSelector":{"future":1,"requirements":[{"key":"team","operator":"In","values":["blue"],"unknown":true}]}}}}`,
	`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"alice","uid":null,"groups":null,"nonResourceAttributes":null,"resourceAttributes":{"verb":"list","resource":"pods","namespace":"apps","name":null,"fieldSelector":null,"labelSelector":{"rawSelector":null,"requirements":[{"key":"team","operator":"In","values":["blue"]}]}}}}`,
}
