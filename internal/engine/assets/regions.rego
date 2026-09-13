package authz.evaluator.regions

unbounded := {"default": true, "prefixes": [], "values": []}

member(region, value) := include if {
	some rule in object.get(region, "values", [])
	rule.value == value
	include := rule.include
} else := prefix_member(region, value)

prefix_member(region, value) := include if {
	matches := [rule |
		some rule in object.get(region, "prefixes", [])
		startswith(value, rule.value)
	]
	count(matches) > 0
	longest := max([count(rule.value) | some rule in matches])
	some rule in matches
	count(rule.value) == longest
	include := rule.include
} else := region.default

single(region) := {"single": true, "value": region.values[0].value} if {
	region.default == false
	count(object.get(region, "prefixes", [])) == 0
	count(object.get(region, "values", [])) == 1
	region.values[0].include == true
} else := {"single": false}

intersects(left, right) if {
	some value in exact_boundaries(left, right)
	member(left, value)
	member(right, value)
}

intersects(left, right) if {
	some prefix in prefix_boundaries(left, right)
	prefix_member(left, prefix)
	prefix_member(right, prefix)
}

exact_boundaries(left, right) := {rule.value |
	some region in [left, right]
	some rule in object.get(region, "values", [])
}

prefix_boundaries(left, right) := boundaries if {
	prefixes := {rule.value |
		some region in [left, right]
		some rule in object.get(region, "prefixes", [])
	}
	boundaries := prefixes | {""}
}
