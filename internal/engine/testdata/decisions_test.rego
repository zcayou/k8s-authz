package authz.evaluator.decisions_test

import data.authz.evaluator.decisions

bootstrap := {"serviceUID": "service", "evaluatorID": "evaluator"}

state(fallback) := {
	"serviceUID": "service",
	"evaluatorID": "evaluator",
	"revision": "sha256:1",
	"endpoints": {"cluster": {"name": "cluster", "whenEvaluationFails": fallback, "callers": [], "authorities": []}},
}

principal := {"user": "alice", "groups": [], "uid": "", "extra": null}

condition_input := {
	"principal": object.union(principal, {"extra": {}}),
	"request": {"nonResourceAttributes": {"path": "/", "verb": "get"}},
}

query := {"regions": {"00/category": {
	"default": false,
	"prefixes": [],
	"values": [{"value": "v:resource", "include": true}],
}}}

test_no_authority_has_no_opinion if {
	result := decisions.evaluate("cluster", principal, query, condition_input) with data.bootstrap as bootstrap
		with data.authz.state as state("Deny")
	result.result == "NoOpinion"
	result.code == "NoMatchingAuthority"
	result.revision == "sha256:1"
}

test_evaluation_failure_answers_with_the_endpoint_fallback if {
	every fallback in ["Deny", "NoOpinion"] {
		result := decisions.evaluation_failure("cluster", "invalid SubjectAccessReview") with data.bootstrap as bootstrap
			with data.authz.state as state(fallback)
		result.result == fallback
		result.code == "EvaluationError"
		result.evaluationError == "invalid SubjectAccessReview"
	}
}

test_no_decision_without_current_state if {
	not decisions.evaluate("cluster", principal, query, condition_input) with data.bootstrap as bootstrap
	not decisions.evaluation_failure("cluster", "invalid SubjectAccessReview") with data.bootstrap as bootstrap
	other := json.patch(state("Deny"), [{"op": "replace", "path": "/evaluatorID", "value": "other"}])
	not decisions.evaluate("cluster", principal, query, condition_input) with data.bootstrap as bootstrap
		with data.authz.state as other
}

conditional_state := {
	"predicates": {
		"alice": {"kind": "Subjects", "subjects": [{"kind": "User", "name": "alice"}]},
		"bob": {"kind": "Subjects", "subjects": [{"kind": "User", "name": "bob"}]},
	},
	"contributions": {
		"unconditional": {"principalIDs": ["alice"]},
		"held": {"principalIDs": ["alice"], "conditionIDs": ["held"]},
		"false": {"principalIDs": ["alice"], "conditionIDs": ["held", "false"]},
		"undefined": {"principalIDs": ["alice"], "conditionIDs": ["undefined"]},
		"other_principal": {"principalIDs": ["bob"], "conditionIDs": ["held"]},
	},
}

conditions_module := {"c_held_allow": true, "c_false_allow": false}

normalized := {"principal": principal, "query": query, "conditionInput": condition_input}

test_eligibility_requires_every_condition_to_hold if {
	eligible := {id |
		some id, _ in conditional_state.contributions
		decisions.eligible(id, normalized)
	} with data.authz.state as conditional_state with data.authz.conditions as conditions_module
	eligible == {"unconditional", "held"}
}

test_conditions_are_undefined_without_a_module if {
	decisions.eligible("unconditional", normalized) with data.authz.state as conditional_state
	not decisions.eligible("held", normalized) with data.authz.state as conditional_state
}

# conflicting fails the whole query whenever it's evaluated.
conflicting(id, condition_input) := held if {
	some held in [is_string(id), is_object(condition_input), false]
}

test_conditions_are_not_evaluated_when_principals_do_not_match if {
	not decisions.eligible("other_principal", normalized) with data.authz.state as conditional_state
		with decisions.condition_holds as conflicting
}

test_conditions_receive_the_condition_input if {
	decisions.condition_holds("held", condition_input) with data.authz.conditions as conditions_module
	not decisions.condition_holds("false", condition_input) with data.authz.conditions as conditions_module
}
