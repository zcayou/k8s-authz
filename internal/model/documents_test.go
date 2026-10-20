package model_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
)

var _ = Describe("Digests", func() {
	It("digest the JSON encoding, preserving large integers and list order", func() {
		value := struct {
			Z uint64   `json:"z"`
			B []string `json:"b"`
			M map[string]int64
		}{Z: math.MaxUint64, B: []string{"second", "first"}, M: map[string]int64{"y": math.MaxInt64, "a": 1}}
		encoded, err := json.Marshal(value)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(encoded)).To(Equal(`{"z":18446744073709551615,"b":["second","first"],"M":{"a":1,"y":9223372036854775807}}`))
		sum := sha256.Sum256(append(encoded, '\n'))
		Expect(model.Digest(value)).To(Equal(hex.EncodeToString(sum[:])))
	})

	It("orders references by every field", func() {
		source := model.SourceKey{Namespace: "control", Name: "local"}
		first := model.Reference{Source: source, Group: api.GroupVersion.Group, Kind: model.KindPolicy, Namespace: "a", Name: "same"}
		second := first
		second.Namespace = "b"
		third := first
		third.Kind = model.KindPolicySet
		references := []model.Reference{third, second, first, second}
		model.SortReferences(references)
		Expect(references).To(Equal([]model.Reference{first, second, second, third}))
	})
})

var _ = Describe("Selections", func() {
	tier := func(operator metav1.LabelSelectorOperator, values ...string) metav1.LabelSelectorRequirement {
		return metav1.LabelSelectorRequirement{Key: "tier", Operator: operator, Values: values}
	}
	frontend := map[string]string{"tier": "frontend"}
	backend := map[string]string{"tier": "backend"}

	DescribeTable("match labels as a Kubernetes label selector does",
		func(requirement metav1.LabelSelectorRequirement, labels map[string]string, matches bool) {
			Expect(model.LabelSelector{requirement}.Matches(labels)).To(Equal(matches))
		},
		Entry("In with a listed value", tier(metav1.LabelSelectorOpIn, "frontend"), frontend, true),
		Entry("In with another value", tier(metav1.LabelSelectorOpIn, "frontend"), backend, false),
		Entry("In without the key", tier(metav1.LabelSelectorOpIn, "frontend"), nil, false),
		Entry("NotIn with a listed value", tier(metav1.LabelSelectorOpNotIn, "frontend"), frontend, false),
		Entry("NotIn with another value", tier(metav1.LabelSelectorOpNotIn, "frontend"), backend, true),
		Entry("NotIn without the key", tier(metav1.LabelSelectorOpNotIn, "frontend"), nil, true),
		Entry("Exists with the key", tier(metav1.LabelSelectorOpExists), backend, true),
		Entry("Exists without the key", tier(metav1.LabelSelectorOpExists), nil, false),
		Entry("DoesNotExist with the key", tier(metav1.LabelSelectorOpDoesNotExist), backend, false),
		Entry("DoesNotExist without the key", tier(metav1.LabelSelectorOpDoesNotExist), nil, true),
	)

	It("matches every label set when empty, and otherwise only those meeting every requirement", func() {
		Expect(model.LabelSelector{}.Matches(nil)).To(BeTrue())
		both := model.LabelSelector{tier(metav1.LabelSelectorOpExists), {Key: "owner", Operator: metav1.LabelSelectorOpIn, Values: []string{"infra"}}}
		Expect(both.Matches(map[string]string{"tier": "frontend", "owner": "infra"})).To(BeTrue())
		Expect(both.Matches(frontend)).To(BeFalse())
	})

	It("matches only the policy group's PolicySets by their labels", func() {
		source := model.SourceKey{Namespace: "control", Name: "local"}
		selection := model.Selection{Source: source, Sets: model.LabelSelector{tier(metav1.LabelSelectorOpIn, "frontend")}}
		set := model.Reference{Source: source, Group: api.GroupVersion.Group, Kind: model.KindPolicySet, Namespace: "apps", Name: "access"}
		Expect(selection.MatchesSet(set, frontend)).To(BeTrue())
		Expect(selection.MatchesSet(set, backend)).To(BeFalse())
		policy := set
		policy.Kind = model.KindPolicy
		Expect(selection.MatchesSet(policy, frontend)).To(BeFalse())
		foreign := set
		foreign.Group = "example.com"
		Expect(selection.MatchesSet(foreign, frontend)).To(BeFalse())
	})
})
