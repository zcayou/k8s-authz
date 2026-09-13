package authz_test

import data.authz

bootstrap := {"serviceUID": "service", "evaluatorID": "evaluator"}

state := {
	"serviceUID": "service",
	"evaluatorID": "evaluator",
	"revision": "sha256:1",
	"endpoints": {"cluster": {"name": "cluster", "whenEvaluationFails": "Deny", "callers": [], "authorities": []}},
}

test_each_state_endpoint_serves_a_decision if {
	endpoints := authz.endpoints with input as {} with data.bootstrap as bootstrap with authz.state as state
	object.keys(endpoints) == {"cluster"}
	endpoints.cluster.decision.kind == "SubjectAccessReview"
	endpoints.cluster.decision.status.denied
	endpoints.cluster.decision.status.evaluationError == "invalid SubjectAccessReview"
}

test_no_endpoint_without_state if {
	endpoints := authz.endpoints with input as {} with data.bootstrap as bootstrap
	count(endpoints) == 0
}
