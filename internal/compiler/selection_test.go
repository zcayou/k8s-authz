package compiler_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/compiler"
	"github.com/zcayou/k8s-authz/internal/model"
)

var _ = Describe("Select", func() {
	instance := model.SourceInstance{Key: model.SourceKey{Namespace: "control", Name: "apps"}, UID: "apps-uid", Origin: "api-apps"}
	entry := model.LabelSelector{{Key: "entry", Operator: metav1.LabelSelectorOpIn, Values: []string{"app"}}}
	owned := model.LabelSelector{{Key: "owner", Operator: metav1.LabelSelectorOpIn, Values: []string{"infra"}}}
	set := func(namespace, name string) model.Reference {
		return model.Reference{Source: instance.Key, Group: api.GroupVersion.Group, Kind: model.KindPolicySet, Namespace: namespace, Name: name}
	}
	var observation model.SourceObservation
	put := func(reference model.Reference, labels map[string]string, valid bool) {
		state := model.DocumentState{Key: model.DocumentKey{Source: instance, Group: reference.Group, Kind: reference.Kind, Namespace: reference.Namespace, Name: reference.Name}, Labels: labels}
		if valid {
			state.Document = &model.Document{Key: state.Key, Set: &model.PolicySet{}}
		}
		observation.Documents[reference] = state
	}
	sources := func() map[model.SourceKey]model.SourceObservation {
		return map[model.SourceKey]model.SourceObservation{instance.Key: observation}
	}
	BeforeEach(func() {
		observation = model.SourceObservation{Instance: instance, Complete: true, Documents: map[model.Reference]model.DocumentState{},
			CollectsNamespaceLabels: true, NamespaceLabels: map[string]map[string]string{"app-a": {"owner": "infra"}, "app-b": {"owner": "infra"}, "other": {"owner": "netsec"}}}
		put(set("app-b", "access"), map[string]string{"entry": "app"}, true)
		put(set("app-a", "access"), map[string]string{"entry": "app"}, false)
		put(set("app-a", "internal"), nil, true)
		put(set("other", "access"), map[string]string{"entry": "app"}, true)
		put(set("unlabeled", "access"), map[string]string{"entry": "app"}, true)
		put(model.Reference{Source: instance.Key, Group: api.GroupVersion.Group, Kind: model.KindPolicyBinding, Namespace: "app-a", Name: "access"}, map[string]string{"entry": "app"}, true)
	})

	It("matches labeled PolicySets, valid or not, in namespaces whose labels match, in reference order", func() {
		Expect(compiler.Select(model.Selection{Source: instance.Key, Namespaces: owned, Sets: entry}, sources(), 256)).To(Equal(compiler.Selected{
			Instance: instance,
			Matches:  []model.Reference{set("app-a", "access"), set("app-b", "access")},
		}))
	})

	It("matches in every namespace with an empty namespace selector, whether or not the source collects namespace labels", func() {
		every := []model.Reference{set("app-a", "access"), set("app-b", "access"), set("other", "access"), set("unlabeled", "access")}
		Expect(compiler.Select(model.Selection{Source: instance.Key, Sets: entry}, sources(), 256).Matches).To(Equal(every))
		observation.CollectsNamespaceLabels, observation.NamespaceLabels = false, nil
		Expect(compiler.Select(model.Selection{Source: instance.Key, Sets: entry}, sources(), 256).Matches).To(Equal(every))
	})

	It("never matches a namespace without collected labels, whatever the namespace selector", func() {
		absent := model.LabelSelector{{Key: "owner", Operator: metav1.LabelSelectorOpDoesNotExist}}
		Expect(compiler.Select(model.Selection{Source: instance.Key, Namespaces: absent, Sets: entry}, sources(), 256).Matches).To(BeEmpty())
	})

	It("succeeds with no matches", func() {
		none := model.LabelSelector{{Key: "entry", Operator: metav1.LabelSelectorOpIn, Values: []string{"none"}}}
		Expect(compiler.Select(model.Selection{Source: instance.Key, Namespaces: owned, Sets: none}, sources(), 256)).To(Equal(compiler.Selected{Instance: instance}))
	})

	It("fails a non-empty namespace selector on a source that doesn't collect namespace labels", func() {
		observation.CollectsNamespaceLabels, observation.NamespaceLabels = false, nil
		Expect(compiler.Select(model.Selection{Source: instance.Key, Namespaces: owned, Sets: entry}, sources(), 256)).To(Equal(compiler.Selected{
			Instance: instance,
			Reason:   model.ReasonNamespaceLabelsNotCollected,
			Message:  "source control/apps doesn't collect namespace labels, which a non-empty namespaceSelector needs",
		}))
	})

	It("fails on a source that isn't registered or has no complete view", func() {
		Expect(compiler.Select(model.Selection{Source: instance.Key, Sets: entry}, nil, 256)).To(Equal(compiler.Selected{
			Reason: model.ReasonSourceUnavailable, Message: "source control/apps isn't a registered PolicySource",
		}))
		observation = model.SourceObservation{Instance: instance, Failure: model.Failure{Reason: string(api.ContributionInert)}}
		Expect(compiler.Select(model.Selection{Source: instance.Key, Sets: entry}, sources(), 256)).To(Equal(compiler.Selected{
			Instance: instance, Reason: model.ReasonSourceUnavailable, Message: "source control/apps is unavailable (Inert)",
		}))
	})

	It("fails as a whole past its match limit", func() {
		selection := model.Selection{Source: instance.Key, Namespaces: owned, Sets: entry}
		Expect(compiler.Select(selection, sources(), 2).Matches).To(HaveLen(2))
		Expect(compiler.Select(selection, sources(), 1)).To(Equal(compiler.Selected{
			Instance: instance, Reason: model.ReasonResourceLimitExceeded, Message: "selection matches 2 PolicySets, more than 1",
		}))
	})
})
