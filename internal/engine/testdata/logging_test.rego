package system.log_test

import data.system.log

test_endpoint_decisions_are_kept if {
	not log.drop with input as {"path": "authz/endpoints/cluster/decision"}
}

test_other_events_are_dropped if {
	every path in [
		"authz/evaluator/installed",
		"authz/state",
		"bootstrap",
		"authz/endpoints/cluster",
		"authz/endpoints/cluster/decision/extra",
	] {
		log.drop with input as {"path": path}
	}
}

test_the_request_is_masked if {
	log.mask == ["/input"]
}
