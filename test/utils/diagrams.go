package utils

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"unicode/utf8"

	"github.com/zcayou/k8s-authz/internal/model"
)

// ValidateRegion rejects a region that isn't in the normal form the algebra
// produces, or whose boundaries JSON encoding would change.
func ValidateRegion(region model.Region) error {
	for _, rules := range [][]model.Override{region.Prefixes, region.Values} {
		seen := make(map[string]bool, len(rules))
		for _, rule := range rules {
			if !utf8.ValidString(rule.Value) || seen[rule.Value] {
				return errors.New("invalid or repeated region boundary")
			}
			seen[rule.Value] = true
		}
	}
	normalized := region.Normalize()
	if region.Default != normalized.Default || !slices.Equal(region.Prefixes, normalized.Prefixes) || !slices.Equal(region.Values, normalized.Values) {
		return errors.New("region is not normalized")
	}
	return nil
}

// ValidateDiagram checks a diagram's structure: bounds, strict dimension
// order, exhaustive and disjoint edges, and indexes consistent with them.
func ValidateDiagram(diagram model.Diagram, maxNodes int) error {
	if len(diagram.Nodes) == 0 || len(diagram.Nodes) > maxNodes {
		return fmt.Errorf("diagram has %d nodes, not 1 to %d", len(diagram.Nodes), maxNodes)
	}
	if int(diagram.Root) >= len(diagram.Nodes) {
		return errors.New("diagram root is missing")
	}
	for id, node := range diagram.Nodes {
		if !utf8.ValidString(node.Dimension) {
			return fmt.Errorf("branch %d has an invalid dimension encoding", id)
		}
		if node.Dimension == "" {
			if err := validateTerminal(node); err != nil {
				return fmt.Errorf("terminal %d: %w", id, err)
			}
			continue
		}
		if len(node.Terminals) != 0 {
			return fmt.Errorf("branch %d has terminals", id)
		}
		union := model.EmptyRegion()
		exact, prefixes := map[string]model.NodeID{}, map[string]model.NodeID{}
		var complement *model.NodeID
		for _, edge := range node.Edges {
			if err := ValidateRegion(edge.Region); err != nil {
				return fmt.Errorf("branch %d: %w", id, err)
			}
			if int(edge.Next) >= len(diagram.Nodes) {
				return fmt.Errorf("branch %d references missing node", id)
			}
			child := diagram.Nodes[edge.Next]
			if child.Dimension != "" && child.Dimension <= node.Dimension {
				return fmt.Errorf("branch %d violates dimension order", id)
			}
			if edge.Region.Empty() || !union.Intersect(edge.Region).Empty() {
				return fmt.Errorf("branch %d has empty or overlapping edges", id)
			}
			union = union.Union(edge.Region)
			for _, value := range edge.Region.Values {
				if value.Include {
					exact[value.Value] = edge.Next
				}
			}
			for _, value := range edge.Region.Prefixes {
				if value.Include {
					prefixes[value.Value] = edge.Next
				}
			}
			if edge.Region.Default {
				complement = new(edge.Next)
			}
		}
		if !union.Complement().Empty() {
			return fmt.Errorf("branch %d is not exhaustive", id)
		}
		if !maps.Equal(exact, node.Exact) || !maps.Equal(prefixes, node.Prefixes) {
			return fmt.Errorf("branch %d has inconsistent indexes", id)
		}
		if (complement == nil) != (node.Complement == nil) || complement != nil && *complement != *node.Complement {
			return fmt.Errorf("branch %d has inconsistent complement", id)
		}
	}
	return nil
}

func validateTerminal(node model.Node) error {
	if len(node.Edges) != 0 || len(node.Exact) != 0 || len(node.Prefixes) != 0 || node.Complement != nil {
		return errors.New("terminal has edges")
	}
	for index, terminal := range node.Terminals {
		if !utf8.ValidString(terminal) || terminal == "" || index > 0 && terminal <= node.Terminals[index-1] {
			return errors.New("invalid or unordered identities")
		}
	}
	return nil
}
