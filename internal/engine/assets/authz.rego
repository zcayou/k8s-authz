package system.authz

default allow := false

allow if {
	input.method == "GET"
	input.path in {["health", "live"], ["health", "ready"], ["metrics"]}
}

# A webhook caller is admitted by its certificate's Common Name, which the
# endpoint's state lists. The TLS handshake has verified its chain.
allow if {
	input.method == "POST"
	count(input.path) == 6
	input.path[0] == "v0"
	input.path[1] == "data"
	input.path[2] == "authz"
	input.path[3] == "endpoints"
	input.path[5] == "decision"
	input.client_certificates[0].Subject.CommonName in data.authz.state.endpoints[input.path[4]].callers
}

allow if {
	management_caller
	input.method == "GET"
	input.path in {["v1", "data", "authz", "state"], ["v1", "data", "authz", "evaluator", "installed"]}
}

allow if {
	management_caller
	input.method == "PUT"
	input.path in {["v1", "data", "authz", "state"], ["v1", "policies", "k8s-authz", "conditions"]}
}

# management_caller is the operator: its leaf carries the bootstrap identity
# and chains to a management root. The handshake pool also holds the webhook
# callers' CA, so the chain is verified again against the management roots
# alone.
management_caller if {
	leaf := input.client_certificates[0]
	leaf.Subject.CommonName == data.bootstrap.management.identity
	intermediates := [certificate_pem(cert.Raw) | some index, cert in input.client_certificates; index > 0]
	some root in data.bootstrap.management.roots
	chain := concat("", array.flatten([root, intermediates, certificate_pem(leaf.Raw)]))
	verified := crypto.x509.parse_and_verify_certificates_with_options(chain, {"KeyUsages": ["KeyUsageClientAuth"]})
	verified[0]
}

certificate_pem(raw) := concat("", ["-----BEGIN CERTIFICATE-----\n", raw, "\n-----END CERTIFICATE-----\n"])
