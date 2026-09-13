package kubernetes

import (
	"cmp"
	"slices"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
)

// Collection is the key ranges a PolicySource collects.
type Collection []api.KeyRange

// NewCollection normalizes a PolicySource's collection: each range's kinds,
// namespaces and names are sorted, and the ranges are sorted with duplicates
// dropped, so an equivalent spec yields an equal collection.
func NewCollection(ranges []api.KeyRange) Collection {
	collection := make(Collection, 0, len(ranges))
	for _, keyRange := range ranges {
		collection = append(collection, api.KeyRange{
			Kinds:      slices.Sorted(slices.Values(keyRange.Kinds)),
			Namespaces: slices.Sorted(slices.Values(keyRange.Namespaces)),
			Names:      slices.Sorted(slices.Values(keyRange.Names)),
		})
	}
	slices.SortFunc(collection, compareRanges)
	return slices.CompactFunc(collection, func(left, right api.KeyRange) bool { return compareRanges(left, right) == 0 })
}

// Collects reports whether the collection covers reference.
func (c Collection) Collects(reference model.Reference) bool {
	documentKind, found := model.DocumentKinds[reference.Kind]
	if !found || documentKind.Resource.Group != reference.Group || documentKind.Namespaced != (reference.Namespace != "") {
		return false
	}
	return slices.ContainsFunc(c, func(keyRange api.KeyRange) bool {
		return slices.Contains(keyRange.Kinds, reference.Kind) &&
			(!documentKind.Namespaced || selects(keyRange.Namespaces, reference.Namespace)) &&
			selects(keyRange.Names, reference.Name)
	})
}

// selects reports whether values holds value or the wildcard.
func selects(values []string, value string) bool {
	return slices.Contains(values, "*") || slices.Contains(values, value)
}

func compareRanges(left, right api.KeyRange) int {
	return cmp.Or(slices.Compare(left.Kinds, right.Kinds), slices.Compare(left.Namespaces, right.Namespaces), slices.Compare(left.Names, right.Names))
}
