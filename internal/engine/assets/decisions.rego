package authz.evaluator.decisions

import data.authz.evaluator.principals
import data.authz.evaluator.traversal

# current holds once the pushed state was compiled for this pod's service
# and evaluator.
current if {
	data.authz.state.serviceUID == data.bootstrap.serviceUID
	data.authz.state.evaluatorID == data.bootstrap.evaluatorID
	data.authz.state.revision != ""
}

predicates_match(ids, principal) if {
	every id in ids {
		principals.matches(data.authz.state.predicates[id], principal)
	}
}

# condition_holds holds when the conditions module's allow rule for the
# condition is true for condition_input. A condition the module doesn't define
# doesn't hold.
condition_holds(id, condition_input) if {
	# Conditions are written against input, and the evaluator supplies theirs
	# by replacing it.
	# regal ignore:with-outside-test-context
	data.authz.conditions[concat("", ["c_", id, "_allow"])] with input as condition_input
}

conditions_hold(ids, condition_input) if {
	every id in ids {
		condition_holds(id, condition_input)
	}
}

# eligible holds when a contribution applies to the request. Its conditions
# run only once its principal predicates match.
eligible(id, normalized) if {
	contribution := data.authz.state.contributions[id]
	predicates_match(contribution.principalIDs, normalized.principal)
	conditions_hold(object.get(contribution, "conditionIDs", []), normalized.conditionInput)
}

failure(id, principal) if {
	issue := data.authz.state.issues[id]
	issue.severity == "Error"
	predicates_match(issue.principalIDs, principal)
}

selected(endpoint, principal) := authority if {
	indexes := [index |
		some index, candidate in endpoint.authorities
		selection_matches(candidate, principal)
	]
	count(indexes) > 0
	authority := endpoint.authorities[min(indexes)]
}

selection_matches(candidate, principal) if {
	count(object.get(candidate, "selectionErrorIDs", [])) > 0
} else if {
	principals.matches(data.authz.state.predicates[candidate.matcherID], principal)
}

has_eligible(terminals, normalized) if {
	some id in terminals
	eligible(id, normalized)
}

covered(reached, normalized) if {
	count(reached) > 0
	every terminals in reached {
		has_eligible(terminals, normalized)
	}
}

eligible_ids(reached, normalized) := sort({id |
	some terminals in reached
	some id in terminals
	eligible(id, normalized)
})

failure_ids(reached, principal) := sort({id |
	some terminals in reached
	some id in terminals
	failure(id, principal)
})

evaluate(endpoint_name, principal, query, condition_input) := result if {
	current
	normalized := {"principal": principal, "query": query, "conditionInput": condition_input}
	endpoint := data.authz.state.endpoints[endpoint_name]
	base := {"endpoint": endpoint_name, "revision": data.authz.state.revision}
	result := evaluate_endpoint(endpoint, normalized, base)
}

# evaluation_failure answers a request the endpoint can't evaluate. Without
# current state the endpoint's fallback is unknown, so the result is undefined
# and the caller's failurePolicy, rendered from the same setting, applies.
evaluation_failure(endpoint_name, message) := failed(
	data.authz.state.endpoints[endpoint_name],
	{"endpoint": endpoint_name, "revision": data.authz.state.revision},
	{"evaluationError": message},
) if {
	current
}

failed(endpoint, base, details) := object.union_n([
	base,
	details,
	{"result": endpoint.whenEvaluationFails, "reason": "EvaluationError", "code": "EvaluationError"},
])

evaluate_endpoint(endpoint, normalized, base) := result if {
	authority := selected(endpoint, normalized.principal)
	result := evaluate_authority(endpoint, authority, normalized, object.union(base, {"authority": authority.name}))
} else := object.union(base, {"result": "NoOpinion", "reason": "NoAuthority", "code": "NoMatchingAuthority"}) if {
	not selected(endpoint, normalized.principal)
}

evaluate_authority(endpoint, authority, normalized, base) := failed(
	endpoint,
	base,
	{"evaluationError": "entry binding unavailable", "issueIDs": authority.selectionErrorIDs},
) if {
	count(object.get(authority, "selectionErrorIDs", [])) > 0
} else := result if {
	authoritative := traversal.evaluate(authority.authoritativeFailureDiagramID, normalized.query)
	ids := failure_ids(authoritative, normalized.principal)
	count(ids) > 0
	result := failed(endpoint, base, {"evaluationError": "authoritative policy unavailable", "issueIDs": ids})
} else := result if {
	authoritative := traversal.evaluate(authority.authoritativeFailureDiagramID, normalized.query)
	count(failure_ids(authoritative, normalized.principal)) == 0
	prohibited := traversal.evaluate(authority.prohibitionDiagramID, normalized.query)
	result := evaluate_prohibition(authority, normalized, prohibited, base)
}

evaluate_prohibition(authority, normalized, prohibited, base) := object.union(
	base,
	{"result": "Deny", "reason": "Prohibited", "code": "RootProhibited", "contributionIDs": ids},
) if {
	ids := eligible_ids(prohibited, normalized)
	count(ids) > 0
} else := evaluate_allow(authority, normalized, base)

# allow_diagrams are the diagrams an authority grants through: its composed
# Allow diagram, or the independent ones when the composed diagram exceeded
# its budget and was omitted.
allow_diagrams(authority) := [authority.composedAllowDiagramID] if {
	object.get(authority, "composedAllowDiagramID", "") != ""
} else := object.get(authority, "independentAllowDiagramIDs", [])

# evaluate_allow grants through the first diagram that covers the request.
# A diagram the traversal can't evaluate grants nothing.
evaluate_allow(authority, normalized, base) := result if {
	proofs := [traversal.evaluate(id, normalized.query) | some id in allow_diagrams(authority)]
	covered_indexes := [index | some index, proof in proofs; covered(proof, normalized)]
	count(covered_indexes) > 0
	result := allowed(base, eligible_ids(proofs[min(covered_indexes)], normalized))
} else := object.union(
	base,
	{"result": authority.fallback, "reason": "NoPolicyAllows", "code": "AuthorityFallback"},
)

allowed(base, ids) := object.union(
	base,
	{"result": "Allow", "reason": "Allowed", "code": "PolicyAllowed", "contributionIDs": ids},
)
