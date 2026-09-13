package authz.evaluator.traversal

import data.authz.evaluator.regions

# evaluate returns the terminals of each terminal node a pushed permission
# diagram reaches for query. The generated point_NNN and walk_NNN levels
# unroll the walk to the diagrams' fixed depth, because Rego has no recursion.
# The compiler partitions every branch's value space and the program keeps
# every query region nonempty, so a walk within that depth always reaches
# a terminal node. seen visits each node once, so the compiled node bound
# limits the walk.
evaluate(diagram_id, query) := terminals if {
	point_query(query)
	start := point_start(data.authz.state.diagrams[diagram_id].root)
	terminals := point_000(diagram_id, query, start).terminals
} else := terminals if {
	not point_query(query)
	diagram := data.authz.state.diagrams[diagram_id]
	terminals := walk_000(diagram, query, frontier_from_point(point_start(diagram.root))).terminals
}

point_start(root) := {"id": root, "broad": false, "done": false}

point_query(query) if {
	every _, region in query.regions {
		regions.single(region).single
	}
}

point_step(diagram_id, query, state) := point_node(data.authz.state.diagrams[diagram_id].nodes[state.id], query, state)

point_node(node, query, state) := {"id": next, "broad": false, "done": false} if {
	object.get(node, "dimension", "") != ""
	single := regions.single(object.get(query.regions, node.dimension, regions.unbounded))
	single.single
	next := concrete_successor(node, single.value)
} else := object.union(state, {"broad": true}) if {
	object.get(node, "dimension", "") != ""
	not regions.single(object.get(query.regions, node.dimension, regions.unbounded)).single
} else := {"done": true, "terminals": [object.get(node, "terminals", [])]} if {
	object.get(node, "dimension", "") == ""
}

frontier_from_point(state) := {
	"frontier": [state.id],
	"seen": set(),
	"terminals": [],
	"done": false,
}

step(diagram, query, state) := result if {
	leaves := [object.get(diagram.nodes[id], "terminals", []) |
		some id in state.frontier
		object.get(diagram.nodes[id], "dimension", "") == ""
	]
	seen := state.seen | {id | some id in state.frontier}
	frontier := sort({next |
		some id in state.frontier
		object.get(diagram.nodes[id], "dimension", "") != ""
		some next in successors(diagram.nodes[id], query)
		not next in seen
	})
	result := {
		"frontier": frontier,
		"seen": seen,
		"terminals": array.concat(state.terminals, leaves),
		"done": count(frontier) == 0,
	}
}

successors(node, query) := [next] if {
	single := regions.single(object.get(query.regions, node.dimension, regions.unbounded))
	single.single
	next := concrete_successor(node, single.value)
} else := [edge.next |
	region := object.get(query.regions, node.dimension, regions.unbounded)
	not regions.single(region).single
	some edge in node.edges
	regions.intersects(region, edge.region)
]

concrete_successor(node, value) := next if {
	next := object.get(object.get(node, "exact", {}), value, null)
	next != null
} else := next if {
	prefixes := [prefix |
		some prefix in object.keys(object.get(node, "prefixes", {}))
		startswith(value, prefix)
	]
	count(prefixes) > 0
	longest := max([count(prefix) | some prefix in prefixes])
	some prefix in prefixes
	count(prefix) == longest
	next := node.prefixes[prefix]
} else := next if {
	next := object.get(node, "complement", null)
	next != null
}
