package model_test

import (
	"slices"

	"github.com/zcayou/k8s-authz/internal/model"
)

// terminals follows diagram from its root for the point that has value in each
// dimension, "" where the point omits one, and returns the terminals
// it reaches.
func terminals(diagram model.Diagram, point map[string]string) []string {
	node := diagram.Nodes[diagram.Root]
	for node.Dimension != "" {
		index := slices.IndexFunc(node.Edges, func(edge model.Edge) bool { return edge.Region.Contains(point[node.Dimension]) })
		if index < 0 {
			return nil
		}
		node = diagram.Nodes[node.Edges[index].Next]
	}
	return node.Terminals
}

// covered reports whether the point reaches a nonempty terminal.
func covered(diagram model.Diagram, point map[string]string) bool {
	return len(terminals(diagram, point)) > 0
}
