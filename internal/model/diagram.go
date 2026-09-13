package model

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const (
	Category          = "00/category"
	APIGroup          = "01/apiGroup"
	APIVersion        = "02/apiVersion"
	Resource          = "03/resource"
	Verb              = "04/verb"
	IngressNamespace  = "05/ingressNamespace"
	AffectedNamespace = "06/affectedNamespace"
	Name              = "07/name"
	LabelPrefix       = "08/label/"
	FieldPrefix       = "09/field/"
	URL               = "10/url"
)

// ErrLimit is wrapped by every error that reports a compilation limit being
// exceeded.
var ErrLimit = errors.New("compilation limit exceeded")

var errUnknownNode = errors.New("unknown diagram node")

type NodeID uint32

type Edge struct {
	Region Region `json:"region"`
	Next   NodeID `json:"next"`
}

type Node struct {
	Dimension  string            `json:"dimension,omitempty"`
	Edges      []Edge            `json:"edges,omitempty"`
	Exact      map[string]NodeID `json:"exact,omitempty"`
	Prefixes   map[string]NodeID `json:"prefixes,omitempty"`
	Complement *NodeID           `json:"complement,omitempty"`
	Terminals  []string          `json:"terminals,omitempty"`
}

type Diagram struct {
	Root  NodeID `json:"root"`
	Nodes []Node `json:"nodes"`
}

// Arena interns ordered diagram nodes up to a fixed node count. Its apply memo
// isn't charged to that count; it lives only as long as the arena. IDs 0 and 1
// are the empty and universal permission terminals.
type Arena struct {
	nodes  []Node
	intern map[string]NodeID
	memo   map[applyKey]NodeID
	limit  int
}

type applyKey struct {
	op   byte
	a, b NodeID
}

func NewArena(limit int) *Arena {
	return &Arena{nodes: []Node{{}, {Terminals: []string{"$"}}}, intern: map[string]NodeID{}, memo: map[applyKey]NodeID{}, limit: limit}
}
func (a *Arena) leaf(labels []string) (NodeID, error) {
	labels = slices.Clone(labels)
	slices.Sort(labels)
	labels = slices.Compact(labels)
	if len(labels) == 0 {
		return 0, nil
	}
	if slices.Equal(labels, []string{"$"}) {
		return 1, nil
	}
	var key strings.Builder
	key.WriteByte('$')
	for _, label := range labels {
		key.WriteString(strconv.Quote(label))
	}
	return a.internNode(key.String(), Node{Terminals: labels})
}

// internNode returns the ID of the node key identifies, allocating node
// under it if it's new. A leaf's key is its sorted labels; a branch's is its
// dimension and its edges' region keys and successors.
func (a *Arena) internNode(key string, node Node) (NodeID, error) {
	if id, exists := a.intern[key]; exists {
		return id, nil
	}
	if len(a.nodes) >= a.limit {
		return 0, fmt.Errorf("permission diagram exceeds %d nodes: %w", a.limit, ErrLimit)
	}
	id := NodeID(len(a.nodes)) //nolint:gosec // The arena limit bounds the node count.
	a.nodes = append(a.nodes, node)
	a.intern[key] = id
	return id, nil
}

func (a *Arena) branch(dimension string, edges []Edge) (NodeID, error) {
	merged := map[NodeID]Region{}
	for _, edge := range edges {
		if edge.Region.Empty() {
			continue
		}
		merged[edge.Next] = merged[edge.Next].Union(edge.Region)
	}
	if len(merged) == 1 {
		for id := range merged {
			return id, nil
		}
	}
	type keyedEdge struct {
		edge Edge
		key  string
	}
	out := make([]keyedEdge, 0, len(merged))
	exact := map[string]NodeID{}
	prefixes := map[string]NodeID{}
	var complement *NodeID
	for id, region := range merged {
		out = append(out, keyedEdge{edge: Edge{Region: region, Next: id}, key: region.Key()})
		for _, value := range region.Values {
			if value.Include {
				exact[value.Value] = id
			}
		}
		for _, prefix := range region.Prefixes {
			if prefix.Include {
				prefixes[prefix.Value] = id
			}
		}
		if region.Default {
			complement = new(id)
		}
	}
	slices.SortFunc(out, func(a, b keyedEdge) int {
		return cmp.Or(strings.Compare(a.key, b.key), cmp.Compare(a.edge.Next, b.edge.Next))
	})
	sortedEdges := make([]Edge, 0, len(out))
	var key strings.Builder
	key.WriteString(strconv.Quote(dimension))
	for _, item := range out {
		sortedEdges = append(sortedEdges, item.edge)
		key.WriteByte(';')
		key.WriteString(item.key)
		key.WriteByte('>')
		key.WriteString(strconv.FormatUint(uint64(item.edge.Next), 10))
	}
	return a.internNode(key.String(), Node{Dimension: dimension, Edges: sortedEdges, Exact: exact, Prefixes: prefixes, Complement: complement})
}

// Cube constructs a conjunction. Unspecified dimensions remain unrestricted.
func (a *Arena) Cube(regions map[string]Region) (NodeID, error) {
	dimensions := make([]string, 0, len(regions))
	for dimension := range regions {
		dimensions = append(dimensions, dimension)
	}
	slices.Sort(dimensions)
	root := NodeID(1)
	for _, dimension := range slices.Backward(dimensions) {
		region := regions[dimension]
		if region.Empty() {
			return 0, nil
		}
		var err error
		root, err = a.branch(dimension, []Edge{{Region: region, Next: root}, {Region: region.Complement(), Next: 0}})
		if err != nil {
			return 0, err
		}
	}
	return root, nil
}

func (a *Arena) Union(left, right NodeID) (NodeID, error) {
	return a.apply('u', left, right)
}
func (a *Arena) Intersect(left, right NodeID) (NodeID, error) {
	return a.apply('i', left, right)
}
func (a *Arena) Subtract(left, right NodeID) (NodeID, error) {
	return a.apply('s', left, right)
}

// UnionAll combines roots in a balanced tree. This avoids repeatedly applying
// a small diagram to an ever-growing accumulator while preserving Union's
// canonical result.
func (a *Arena) UnionAll(roots []NodeID) (NodeID, error) {
	if len(roots) == 0 {
		return 0, nil
	}
	work := slices.Clone(roots)
	for len(work) > 1 {
		write := 0
		for read := 0; read+1 < len(work); read += 2 {
			root, err := a.Union(work[read], work[read+1])
			if err != nil {
				return 0, err
			}
			work[write] = root
			write++
		}
		if len(work)%2 != 0 {
			work[write] = work[len(work)-1]
			write++
		}
		work = work[:write]
	}
	return work[0], nil
}

func (a *Arena) apply(op byte, left, right NodeID) (NodeID, error) {
	if int(left) >= len(a.nodes) || int(right) >= len(a.nodes) {
		return 0, errUnknownNode
	}
	key := applyKey{op, left, right}
	if result, exists := a.memo[key]; exists {
		return result, nil
	}
	l, r := a.nodes[left], a.nodes[right]
	if l.Dimension == "" && r.Dimension == "" {
		var labels []string
		switch op {
		case 'u':
			labels = append(slices.Clone(l.Terminals), r.Terminals...)
		case 'i':
			if len(r.Terminals) != 0 {
				labels = l.Terminals
			}
		case 's':
			if len(r.Terminals) == 0 {
				labels = l.Terminals
			}
		default:
			return 0, errors.New("unknown diagram operation")
		}
		return a.leaf(labels)
	}
	dimension := l.Dimension
	if dimension == "" || r.Dimension != "" && r.Dimension < dimension {
		dimension = r.Dimension
	}
	le, re := l.Edges, r.Edges
	if l.Dimension != dimension {
		le = []Edge{{Region: AnyRegion(), Next: left}}
	}
	if r.Dimension != dimension {
		re = []Edge{{Region: AnyRegion(), Next: right}}
	}
	edges := make([]Edge, 0, len(le)+len(re))
	for _, one := range le {
		for _, two := range re {
			region := one.Region.Intersect(two.Region)
			if region.Empty() {
				continue
			}
			next, err := a.apply(op, one.Next, two.Next)
			if err != nil {
				return 0, err
			}
			edges = append(edges, Edge{Region: region, Next: next})
		}
	}
	result, err := a.branch(dimension, edges)
	if err == nil {
		a.memo[key] = result
	}
	return result, err
}

// Label attaches one contribution identity to the nonempty regions of a permission.
func (a *Arena) Label(root NodeID, label string) (NodeID, error) {
	if int(root) >= len(a.nodes) {
		return 0, errUnknownNode
	}
	memo := map[NodeID]NodeID{}
	var visit func(NodeID) (NodeID, error)
	visit = func(id NodeID) (NodeID, error) {
		if result, exists := memo[id]; exists {
			return result, nil
		}
		node := a.nodes[id]
		if node.Dimension == "" {
			if len(node.Terminals) == 0 {
				return 0, nil
			}
			return a.leaf([]string{label})
		}
		edges := make([]Edge, 0, len(node.Edges))
		for _, edge := range node.Edges {
			next, err := visit(edge.Next)
			if err != nil {
				return 0, err
			}
			edges = append(edges, Edge{Region: edge.Region, Next: next})
		}
		result, err := a.branch(node.Dimension, edges)
		if err == nil {
			memo[id] = result
		}
		return result, err
	}
	return visit(root)
}

// Snapshot retains only reachable nodes and assigns deterministic dense IDs.
func (a *Arena) Snapshot(root NodeID) Diagram {
	out := Diagram{}
	remap := map[NodeID]NodeID{}
	var visit func(NodeID) NodeID
	visit = func(old NodeID) NodeID {
		if id, exists := remap[old]; exists {
			return id
		}
		id := NodeID(len(out.Nodes)) //nolint:gosec // A snapshot holds at most the arena's nodes.
		remap[old] = id
		out.Nodes = append(out.Nodes, Node{})
		node := a.nodes[old]
		copyNode := Node{Dimension: node.Dimension, Terminals: slices.Clone(node.Terminals)}
		for _, edge := range node.Edges {
			copyNode.Edges = append(copyNode.Edges, Edge{Region: edge.Region, Next: visit(edge.Next)})
		}
		if node.Exact != nil {
			copyNode.Exact = map[string]NodeID{}
			for value, next := range node.Exact {
				copyNode.Exact[value] = remap[next]
			}
		}
		if node.Prefixes != nil {
			copyNode.Prefixes = map[string]NodeID{}
			for value, next := range node.Prefixes {
				copyNode.Prefixes[value] = remap[next]
			}
		}
		if node.Complement != nil {
			copyNode.Complement = new(remap[*node.Complement])
		}
		out.Nodes[id] = copyNode
		return id
	}
	out.Root = visit(root)
	return out
}

// Import copies a snapshot of another arena into this one, charging its nodes
// to this arena's budget. Shared subgraphs retain their interning identity.
func (a *Arena) Import(diagram Diagram) (NodeID, error) {
	copied := map[NodeID]NodeID{}
	var visit func(NodeID) (NodeID, error)
	visit = func(id NodeID) (NodeID, error) {
		if value, ok := copied[id]; ok {
			return value, nil
		}
		if int(id) >= len(diagram.Nodes) {
			return 0, errUnknownNode
		}
		node := diagram.Nodes[id]
		if node.Dimension == "" {
			value, err := a.leaf(node.Terminals)
			if err == nil {
				copied[id] = value
			}
			return value, err
		}
		edges := make([]Edge, 0, len(node.Edges))
		for _, edge := range node.Edges {
			next, err := visit(edge.Next)
			if err != nil {
				return 0, err
			}
			edges = append(edges, Edge{Region: edge.Region, Next: next})
		}
		value, err := a.branch(node.Dimension, edges)
		if err == nil {
			copied[id] = value
		}
		return value, err
	}
	return visit(diagram.Root)
}
