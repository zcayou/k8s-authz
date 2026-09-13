package authz

import data.authz.program.kubernetes

# METADATA
# description: |
#   endpoints serves each endpoint in the pushed state at
#   /v0/data/authz/endpoints/<name>/decision. Without state no endpoint
#   exists, so the caller's failurePolicy answers.
# entrypoint: true
endpoints[name] := {"decision": kubernetes.response(name, input)} if {
	some name, _ in data.authz.state.endpoints
}
