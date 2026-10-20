package kubernetes

import (
	"cmp"
	"slices"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
)

// Collection is what a PolicySource collects: its key ranges, and whether
// it reads the labels of the namespaces they cover.
type Collection struct {
	Ranges          []api.KeyRange `json:"ranges"`
	NamespaceLabels bool           `json:"namespaceLabels"`
}

// NewCollection normalizes a PolicySource's collection: each range's kinds,
// namespaces and names are sorted, and the ranges are sorted with duplicates
// dropped, so an equivalent spec yields an equal collection.
func NewCollection(spec api.PolicySourceSpec) Collection {
	ranges := make([]api.KeyRange, 0, len(spec.Collection))
	for _, keyRange := range spec.Collection {
		ranges = append(ranges, api.KeyRange{
			Kinds:      slices.Sorted(slices.Values(keyRange.Kinds)),
			Namespaces: slices.Sorted(slices.Values(keyRange.Namespaces)),
			Names:      slices.Sorted(slices.Values(keyRange.Names)),
		})
	}
	slices.SortFunc(ranges, compareRanges)
	return Collection{
		Ranges:          slices.CompactFunc(ranges, func(left, right api.KeyRange) bool { return compareRanges(left, right) == 0 }),
		NamespaceLabels: spec.NamespaceLabels == api.NamespaceLabelsCollect,
	}
}

// Collects reports whether the collection covers reference.
func (c Collection) Collects(reference model.Reference) bool {
	documentKind, found := model.DocumentKinds[reference.Kind]
	if !found || documentKind.Resource.Group != reference.Group || documentKind.Namespaced != (reference.Namespace != "") {
		return false
	}
	return slices.ContainsFunc(c.Ranges, func(keyRange api.KeyRange) bool {
		return slices.Contains(keyRange.Kinds, reference.Kind) &&
			(!documentKind.Namespaced || selects(keyRange.Namespaces, reference.Namespace)) &&
			selects(keyRange.Names, reference.Name)
	})
}

// CollectsNamespaceLabels reports whether the collection reads namespace
// labels.
func (c Collection) CollectsNamespaceLabels() bool {
	return c.NamespaceLabels
}

// CollectsNamespace reports whether the collection reads namespace's labels:
// whether it reads namespace labels and a range covers namespace.
func (c Collection) CollectsNamespace(namespace string) bool {
	return c.NamespaceLabels && slices.ContainsFunc(c.Ranges, func(keyRange api.KeyRange) bool {
		return selects(keyRange.Namespaces, namespace)
	})
}

// selects reports whether values holds value or the wildcard.
func selects(values []string, value string) bool {
	return slices.Contains(values, "*") || slices.Contains(values, value)
}

func compareRanges(left, right api.KeyRange) int {
	return cmp.Or(slices.Compare(left.Kinds, right.Kinds), slices.Compare(left.Namespaces, right.Namespaces), slices.Compare(left.Names, right.Names))
}
