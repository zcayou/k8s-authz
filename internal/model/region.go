package model

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
)

// Region describes a string set using a default and disjointly interpreted
// overrides. Exact values take precedence over the longest matching prefix.
type Region struct {
	Default  bool       `json:"default"`
	Prefixes []Override `json:"prefixes,omitempty"`
	Values   []Override `json:"values,omitempty"`
}

// Override changes membership at one exact value or prefix boundary.
type Override struct {
	Value   string `json:"value"`
	Include bool   `json:"include"`
}

func AnyRegion() Region {
	return Region{Default: true}
}
func EmptyRegion() Region {
	return Region{}
}
func Values(values ...string) Region {
	r := Region{}
	for _, value := range values {
		r.Values = append(r.Values, Override{Value: value, Include: true})
	}
	return r.Normalize()
}
func Prefix(value string) Region {
	if value == "" {
		return AnyRegion()
	}
	return Region{Prefixes: []Override{{Value: value, Include: true}}}
}

func (r Region) prefixContains(value string) bool {
	result, longest := r.Default, -1
	for _, rule := range r.Prefixes {
		if len(rule.Value) > longest && strings.HasPrefix(value, rule.Value) {
			result, longest = rule.Include, len(rule.Value)
		}
	}
	return result
}

func (r Region) Contains(value string) bool {
	index, found := slices.BinarySearchFunc(r.Values, value, func(rule Override, value string) int {
		return strings.Compare(rule.Value, value)
	})
	if found {
		return r.Values[index].Include
	}
	return r.prefixContains(value)
}

// Normalize removes redundant boundaries and imposes deterministic ordering.
// Constructors and algebra operations always return normalized regions.
func (r Region) Normalize() Region {
	prefixes := slices.Clone(r.Prefixes)
	slices.SortFunc(prefixes, func(a, b Override) int {
		return cmp.Or(cmp.Compare(len(a.Value), len(b.Value)), strings.Compare(a.Value, b.Value))
	})
	out := Region{Default: r.Default}
	for _, rule := range prefixes {
		if rule.Value == "" {
			out.Default = rule.Include
			continue
		}
		if out.prefixContains(rule.Value) != rule.Include {
			out.Prefixes = append(out.Prefixes, rule)
		}
	}
	values := slices.Clone(r.Values)
	slices.SortFunc(values, func(a, b Override) int { return strings.Compare(a.Value, b.Value) })
	for _, rule := range values {
		if out.prefixContains(rule.Value) != rule.Include {
			if len(out.Values) > 0 && out.Values[len(out.Values)-1].Value == rule.Value {
				out.Values[len(out.Values)-1] = rule
			} else {
				out.Values = append(out.Values, rule)
			}
		}
	}
	return out
}

func (r Region) Complement() Region {
	out := Region{Default: !r.Default}
	for _, rule := range r.Prefixes {
		out.Prefixes = append(out.Prefixes, Override{Value: rule.Value, Include: !rule.Include})
	}
	for _, rule := range r.Values {
		out.Values = append(out.Values, Override{Value: rule.Value, Include: !rule.Include})
	}
	return out.Normalize()
}

func (r Region) Union(other Region) Region {
	return combineRegions(r, other, func(a, b bool) bool { return a || b })
}
func (r Region) Intersect(other Region) Region {
	return combineRegions(r, other, func(a, b bool) bool { return a && b })
}
func (r Region) Subtract(other Region) Region {
	return r.Intersect(other.Complement())
}

func combineRegions(a, b Region, operation func(bool, bool) bool) Region {
	if normalizedValuesOnly(a) && normalizedValuesOnly(b) {
		return combineValueRegions(a, b, operation)
	}
	out := Region{Default: operation(a.Default, b.Default)}
	prefixes, values := map[string]struct{}{}, map[string]struct{}{}
	for _, input := range []Region{a, b} {
		for _, rule := range input.Prefixes {
			prefixes[rule.Value] = struct{}{}
		}
		for _, rule := range input.Values {
			values[rule.Value] = struct{}{}
		}
	}
	for value := range prefixes {
		out.Prefixes = append(out.Prefixes, Override{Value: value, Include: operation(a.prefixContains(value), b.prefixContains(value))})
	}
	for value := range values {
		out.Values = append(out.Values, Override{Value: value, Include: operation(a.Contains(value), b.Contains(value))})
	}
	return out.Normalize()
}

func normalizedValuesOnly(region Region) bool {
	if len(region.Prefixes) != 0 {
		return false
	}
	for index, rule := range region.Values {
		if rule.Include == region.Default || index > 0 && region.Values[index-1].Value >= rule.Value {
			return false
		}
	}
	return true
}

func combineValueRegions(a, b Region, operation func(bool, bool) bool) Region {
	out := Region{Default: operation(a.Default, b.Default), Values: make([]Override, 0, len(a.Values)+len(b.Values))}
	left, right := 0, 0
	for left < len(a.Values) || right < len(b.Values) {
		var value string
		leftIncludes, rightIncludes := a.Default, b.Default
		switch {
		case right == len(b.Values) || left < len(a.Values) && a.Values[left].Value < b.Values[right].Value:
			value = a.Values[left].Value
			leftIncludes = a.Values[left].Include
			left++
		case left == len(a.Values) || b.Values[right].Value < a.Values[left].Value:
			value = b.Values[right].Value
			rightIncludes = b.Values[right].Include
			right++
		default:
			value = a.Values[left].Value
			leftIncludes = a.Values[left].Include
			rightIncludes = b.Values[right].Include
			left++
			right++
		}
		include := operation(leftIncludes, rightIncludes)
		if include != out.Default {
			out.Values = append(out.Values, Override{Value: value, Include: include})
		}
	}
	if len(out.Values) == 0 {
		out.Values = nil
	}
	return out
}

// Empty tests exact inclusions and the residual space under included prefixes.
// It only descends where an exact exclusion removes the prefix itself, so long
// boundaries do not cause byte-by-byte recursive traversal.
func (r Region) Empty() bool {
	for _, rule := range r.Values {
		if rule.Include && r.Contains(rule.Value) {
			return false
		}
	}
	pending := []string{}
	if r.Default {
		pending = append(pending, "")
	}
	for _, rule := range r.Prefixes {
		if rule.Include {
			pending = append(pending, rule.Value)
		}
	}
	for len(pending) > 0 {
		prefix := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if r.Contains(prefix) {
			return false
		}
		if !r.prefixContains(prefix) {
			continue
		}
		children := make(map[byte]struct{})
		for _, rules := range [][]Override{r.Prefixes, r.Values} {
			for _, rule := range rules {
				if len(rule.Value) > len(prefix) && strings.HasPrefix(rule.Value, prefix) {
					children[rule.Value[len(prefix)]] = struct{}{}
				}
			}
		}
		if len(children) < 256 {
			return false
		}
		for child := range children {
			pending = append(pending, prefix+string([]byte{child}))
		}
	}
	return true
}

func (r Region) Key() string {
	var out strings.Builder
	out.WriteString(strconv.FormatBool(r.Default))
	for _, rules := range [][]Override{r.Prefixes, r.Values} {
		out.WriteByte('|')
		for _, rule := range rules {
			out.WriteString(strconv.Quote(rule.Value))
			out.WriteString(strconv.FormatBool(rule.Include))
		}
	}
	return out.String()
}

const Absent = "\x00absent"

// Atom separates literal values, including empty strings, from special categories.
func Atom(value string) string {
	return "v:" + value
}
func NamedNamespaces() Region {
	return Prefix("v:").Subtract(Values(Atom("")))
}
func PresentValues() Region {
	return Prefix("v:")
}

// NamespaceCubes scopes a rule to namespaces. nil leaves it unscoped, "*"
// is every named namespace and "" is requests without a namespace. A request
// without a namespace is kept apart from the named namespaces it may affect.
func NamespaceCubes(namespaces []string) []Cube {
	if namespaces == nil {
		return []Cube{{}}
	}
	named := EmptyRegion()
	emptyIngress := false
	for _, namespace := range namespaces {
		switch namespace {
		case "":
			emptyIngress = true
		case "*":
			named = named.Union(NamedNamespaces())
		default:
			named = named.Union(Values(Atom(namespace)))
		}
	}
	cubes := []Cube{}
	if !named.Empty() {
		cubes = append(cubes, Cube{AffectedNamespace: named})
	}
	if emptyIngress {
		cubes = append(cubes, Cube{IngressNamespace: Values(Atom(""))})
	}
	return cubes
}
