package authz.evaluator.installed_test

import data.authz.evaluator.installed

test_empty_without_state_or_module if {
	installed.revision == ""
	installed.conditions_digest == ""
}

test_reports_the_state_revision_and_module_digest if {
	installed.revision == "sha256:state" with data.authz.state as {"revision": "sha256:state"}
	installed.conditions_digest == "sha256:module" with data.authz.conditions as {"digest": "sha256:module"}
}

test_reports_each_without_the_other if {
	installed.conditions_digest == "" with data.authz.state as {"revision": "sha256:state"}
	installed.revision == "" with data.authz.conditions as {"digest": "sha256:module"}
}
