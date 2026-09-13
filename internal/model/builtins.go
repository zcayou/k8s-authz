package model

import "slices"

// BuiltinSet is a sorted set of Rego builtin names. It's never modified
// in place, so sets are safely shared.
type BuiltinSet []string

// NewBuiltinSet returns the set of names.
func NewBuiltinSet(names []string) BuiltinSet {
	set := slices.Clone(names)
	slices.Sort(set)
	return slices.Compact(set)
}

// Intersect returns the names in both s and other.
func (s BuiltinSet) Intersect(other BuiltinSet) BuiltinSet {
	result := BuiltinSet{}
	for _, name := range s {
		if _, found := slices.BinarySearch(other, name); found {
			result = append(result, name)
		}
	}
	return result
}

// Missing returns the names of names that s doesn't contain.
func (s BuiltinSet) Missing(names BuiltinSet) BuiltinSet {
	var missing BuiltinSet
	for _, name := range names {
		if _, found := slices.BinarySearch(s, name); !found {
			missing = append(missing, name)
		}
	}
	return missing
}
