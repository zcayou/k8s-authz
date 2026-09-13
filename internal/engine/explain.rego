package authz.explain

import data.authz.evaluator.decisions
import data.authz.evaluator.traversal
import data.authz.program.kubernetes

# explanation evaluates input.request on input.endpoint as the engine does.
# It adds the normalized principal, for each diagram the deciding authority
# reads, the terminals the request reaches that apply to the principal, and
# whether each of those terminals' conditions held.
explanation := object.union(
	{"decision": kubernetes.decision(input.endpoint, input.request), "terminals": terminals, "conditions": conditions},
	principal,
)

normalized := kubernetes.normalize(input.request)

default principal := {}

principal := {"principal": normalized.principal} if {
	normalized.valid
}

authority := candidate if {
	name := kubernetes.decision(input.endpoint, input.request).authority
	some candidate in data.authz.state.endpoints[input.endpoint].authorities
	candidate.name == name
}

diagrams contains authority.prohibitionDiagramID

diagrams contains authority.authoritativeFailureDiagramID

diagrams contains id if {
	some id in decisions.allow_diagrams(authority)
}

diagrams contains proof.diagramID if {
	some proof in data.authz.state.exclusions
	proof.endpoint == input.endpoint
	proof.authority == authority.name
}

terminals[id] := reached(id) if {
	some id in diagrams
}

reached(diagram_id) := sort({id |
	normalized.valid
	some ids in traversal.evaluate(diagram_id, normalized.query)
	some id in ids
	applies(id)
})

applies(id) if {
	decisions.predicates_match(data.authz.state.contributions[id].principalIDs, normalized.principal)
}

applies(id) if {
	decisions.predicates_match(data.authz.state.issues[id].principalIDs, normalized.principal)
}

applies(id) if {
	decisions.predicates_match(data.authz.state.exclusions[id].principalIDs, normalized.principal)
}

conditions[id] := condition_held(id) if {
	some reached in terminals
	some terminal in reached
	some id in object.get(data.authz.state.contributions, [terminal, "conditionIDs"], [])
}

default condition_held(_) := false

condition_held(id) if {
	decisions.condition_holds(id, normalized.conditionInput)
}
