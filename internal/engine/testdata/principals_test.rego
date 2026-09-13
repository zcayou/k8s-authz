package authz.evaluator.principals_test

import data.authz.evaluator.principals

alice := {"user": "oidc:alice", "groups": ["team:elk"], "uid": "uid-7", "extra": {"scope": ["read", "prod"]}}

requirements(items) := {"kind": "Requirements", "requirements": items}

user(name) := {"user": name, "groups": [], "uid": "", "extra": null}

groups(names) := {"user": "", "groups": names, "uid": "", "extra": null}

extra(values) := {"user": "", "groups": [], "uid": "", "extra": values}

test_subjects_match_any_user_or_group if {
	subjects := {"kind": "Subjects", "subjects": [{"kind": "User", "name": "bob"}, {"kind": "Group", "name": "team:elk"}]}
	principals.matches(subjects, alice)
	not principals.matches(subjects, user("carol"))
}

test_empty_subjects_match_nobody_and_empty_requirements_everybody if {
	not principals.matches({"kind": "Subjects"}, alice)
	principals.matches(requirements([]), user(""))
}

test_requirements_are_a_conjunction if {
	matcher := requirements([
		{"kind": "User", "operator": "StartsWith", "values": ["oidc:"]},
		{"kind": "Group", "operator": "In", "values": ["team:elk"]},
		{"kind": "UID", "operator": "In", "values": ["uid-7"]},
		{"kind": "Extra", "key": "scope", "operator": "In", "values": ["read"]},
		{"kind": "Extra", "key": "scope", "operator": "In", "values": ["prod"]},
		{"kind": "Group", "operator": "NotStartsWith", "values": ["suspended:"]},
	])
	principals.matches(matcher, alice)
	not principals.matches(matcher, object.union(alice, {"groups": ["team:elk", "suspended:security"]}))
	not principals.matches(matcher, object.union(alice, {"uid": "uid-8"}))
}

test_prefixes_are_literal_and_case_sensitive if {
	starts := requirements([{"kind": "Group", "operator": "StartsWith", "values": ["oidc:"]}])
	principals.matches(starts, groups(["oidc:engineering"]))
	not principals.matches(starts, groups(["OIDC:engineering"]))
	exact := requirements([{"kind": "Group", "operator": "In", "values": ["oidc:*"]}])
	not principals.matches(exact, groups(["oidc:engineering"]))
}

test_missing_extra_differs_from_present_empty_extra if {
	exists := requirements([{"kind": "Extra", "key": "approved", "operator": "Exists"}])
	not principals.matches(exists, user(""))
	principals.matches(exists, extra({"approved": []}))
	absent := requirements([{"kind": "Extra", "key": "approved", "operator": "DoesNotExist"}])
	principals.matches(absent, user(""))
	excluded := requirements([{"kind": "Extra", "key": "approved", "operator": "NotIn", "values": ["true"]}])
	principals.matches(excluded, user(""))
}

test_service_account_requirements_need_a_service_account_user if {
	not_deployer := {"kind": "ServiceAccount", "namespace": "build", "operator": "NotIn", "values": ["deployer"]}
	principals.matches(requirements([not_deployer]), user("alice"))
	matcher := requirements([not_deployer, {"kind": "ServiceAccount", "namespace": "build", "operator": "Exists"}])
	not principals.matches(matcher, user("alice"))
	not principals.matches(matcher, user("system:serviceaccount:other:reader"))
	not principals.matches(matcher, user("system:serviceaccount:build:deployer"))
	principals.matches(matcher, user("system:serviceaccount:build:reader"))
}
