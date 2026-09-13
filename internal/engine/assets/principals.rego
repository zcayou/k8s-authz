package authz.evaluator.principals

matches(matcher, principal) if {
	matcher.kind == "Subjects"
	some subject in object.get(matcher, "subjects", [])
	subject_matches(subject, principal)
}

matches(matcher, principal) if {
	matcher.kind == "Requirements"
	every requirement in object.get(matcher, "requirements", []) {
		requirement_matches(requirement, principal)
	}
}

subject_matches(subject, principal) if {
	subject.kind == "User"
	principal.user == subject.name
}

subject_matches(subject, principal) if {
	subject.kind == "Group"
	subject.name in principal.groups
}

selected(r, p) := {"values": [p.user], "present": true} if {
	r.kind == "User"
	p.user != ""
} else := {"values": p.groups, "present": count(p.groups) > 0} if {
	r.kind == "Group"
	is_array(p.groups)
} else := {"values": [p.uid], "present": true} if {
	r.kind == "UID"
	p.uid != ""
} else := {"values": p.extra[r.key], "present": true} if {
	r.kind == "Extra"
	r.key in object.keys(p.extra)
} else := {"values": [name], "present": true} if {
	r.kind == "ServiceAccount"
	prefix := concat("", ["system:serviceaccount:", r.namespace, ":"])
	startswith(p.user, prefix)
	name := substring(p.user, count(prefix), -1)
	count(name) <= 253
	regex.match(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`, name)
} else := {"values": [], "present": false}

requirement_matches(r, p) if {
	r.operator == "Exists"
	selected(r, p).present
}

requirement_matches(r, p) if {
	r.operator == "DoesNotExist"
	not selected(r, p).present
}

requirement_matches(r, p) if {
	r.operator == "In"
	equal_operand(r, selected(r, p).values)
}

requirement_matches(r, p) if {
	r.operator == "NotIn"
	not equal_operand(r, selected(r, p).values)
}

requirement_matches(r, p) if {
	r.operator == "StartsWith"
	prefix_operand(r, selected(r, p).values)
}

requirement_matches(r, p) if {
	r.operator == "NotStartsWith"
	not prefix_operand(r, selected(r, p).values)
}

equal_operand(r, values) if {
	some value in values
	value in r.values
}

prefix_operand(r, values) if {
	some value in values
	some prefix in r.values
	startswith(value, prefix)
}
