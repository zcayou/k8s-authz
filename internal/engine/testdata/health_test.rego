package system.health_test

import data.system.health

bootstrap := {"serviceUID": "service", "evaluatorID": "evaluator"}

test_live_without_state if {
	health.live with data.bootstrap as bootstrap
}

test_unready_without_state if {
	not health.ready with data.bootstrap as bootstrap
}

test_ready_with_state_for_its_service_and_evaluator if {
	health.ready with data.bootstrap as bootstrap
		with data.authz.state as {"serviceUID": "service", "evaluatorID": "evaluator", "revision": "sha256:1"}
}

test_unready_with_state_for_another_service_or_evaluator if {
	every state in [
		{"serviceUID": "other", "evaluatorID": "evaluator", "revision": "sha256:1"},
		{"serviceUID": "service", "evaluatorID": "other", "revision": "sha256:1"},
		{"serviceUID": "service", "evaluatorID": "evaluator", "revision": ""},
	] {
		not health.ready with data.bootstrap as bootstrap with data.authz.state as state
	}
}

state := {"serviceUID": "service", "evaluatorID": "evaluator", "revision": "sha256:1"}

test_ready_whatever_the_conditions_module if {
	every module in [{}, {"digest": "sha256:newer"}] {
		health.ready with data.bootstrap as bootstrap
			with data.authz.state as object.union(state, {"conditionsDigest": "sha256:older"})
			with data.authz.conditions as module
	}
}
