package system.log

# mask erases the request, which carries the caller's identity and the
# requested object, from decision logs.
mask := ["/input"]

# drop discards every event but an endpoint's decision, such as the operator's
# management reads.
drop if not endpoint_decision

endpoint_decision if {
	segments := split(input.path, "/")
	count(segments) == 4
	segments[0] == "authz"
	segments[1] == "endpoints"
	segments[3] == "decision"
}
