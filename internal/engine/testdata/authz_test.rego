package system.authz_test

import data.system.authz

# The fixture certificates are valid from 2026 to 2126. The management
# fixtures chain to management_root; caller_ca_operator_name carries the
# management identity but is issued by the webhook callers' CA.

management_root := "-----BEGIN CERTIFICATE-----\nMIIBZDCCAQmgAwIBAgIBATAKBggqhkjOPQQDAjAYMRYwFAYDVQQDEw1tYW5hZ2Vt\nZW50LWNhMCAXDTI2MDEwMTAwMDAwMFoYDzIxMjYwMTAxMDAwMDAwWjAYMRYwFAYD\nVQQDEw1tYW5hZ2VtZW50LWNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8Q0E\nuzMopgs9tHxbjdQWQ49KNVPS+56l9WUiu2Fn0PZ0u162wqN+se5gRLM+ZO3+XhFI\nDDMG/nTJOVvYUXcUc6NCMEAwDgYDVR0PAQH/BAQDAgKEMA8GA1UdEwEB/wQFMAMB\nAf8wHQYDVR0OBBYEFLjmZfisXtSUrskT3cRT+z/bqUJjMAoGCCqGSM49BAMCA0kA\nMEYCIQDJBjFN3eVPx9BWTLDfohguLGIaLTtKKRsML3TMOMG24AIhANbmTcYazagP\nOayBTQaQx2MncsEI+W9ctX8QRbbmCytZ\n-----END CERTIFICATE-----\n"

operator := {"Raw": "MIIBZTCCAQqgAwIBAgIBAjAKBggqhkjOPQQDAjAYMRYwFAYDVQQDEw1tYW5hZ2VtZW50LWNhMCAXDTI2MDEwMTAwMDAwMFoYDzIxMjYwMTAxMDAwMDAwWjATMREwDwYDVQQDEwhvcGVyYXRvcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPwWNV2xAk13tB+1KeEQUE3qOLM+GbZ0KRPeGHN/uXURvlWvLmNbMZoj+Rus/Dn1ZSv+FHj+TPeNeGPmUbYlTJ6jSDBGMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAjAfBgNVHSMEGDAWgBS45mX4rF7UlK7JE93EU/s/26lCYzAKBggqhkjOPQQDAgNJADBGAiEAlmhAQwGTasevKWa/0KiVJlQYRxaLech7wB1qIZ9CmvwCIQDiJn+1JxyC5OoBllLcQQ6ZORomB+z80RvC48GT9eF58A==", "Subject": {"CommonName": "operator"}}

management_ca_other_name := {"Raw": "MIIBajCCARCgAwIBAgIBAzAKBggqhkjOPQQDAjAYMRYwFAYDVQQDEw1tYW5hZ2VtZW50LWNhMCAXDTI2MDEwMTAwMDAwMFoYDzIxMjYwMTAxMDAwMDAwWjAZMRcwFQYDVQQDEw53ZWJob29rLWNhbGxlcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOdV8YSoMD3+zxA68ndD4ef4dpKwh4QxRDi0UQjsvGpDif1gZiFOxuxKEM5glLOeW+Exc30UP/q5RmW9WWwtlIajSDBGMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAjAfBgNVHSMEGDAWgBS45mX4rF7UlK7JE93EU/s/26lCYzAKBggqhkjOPQQDAgNIADBFAiBBU8Z7N02YRDVY8vMy7LV6M1LMRe72YXp/EKb13ZlIuQIhAJQ3Fhqjn44b7gAyMldD3Xfs2wiOdTxaJTZ+LVcOuvli", "Subject": {"CommonName": "webhook-caller"}}

caller_ca_operator_name := {"Raw": "MIIBYDCCAQagAwIBAgIBBTAKBggqhkjOPQQDAjAUMRIwEAYDVQQDEwljYWxsZXItY2EwIBcNMjYwMTAxMDAwMDAwWhgPMjEyNjAxMDEwMDAwMDBaMBMxETAPBgNVBAMTCG9wZXJhdG9yMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbLVXSXtTB6m7o9F0LdTItYsYsbVsMR1+carHgLLLV85+ygteCL/yezDxOahcHR05X5s+JsovGaK+1x1IHuwWqaNIMEYwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFBasQM3T16Rq86787G/bFTLZxeJZMAoGCCqGSM49BAMCA0gAMEUCIQCOnngdL1rATu0qBb0ZcJ3HpdoU+uJoJjV27dBrUvp/9wIgOg5r7mbIg9RpvWYhox9+/dqtzFnVMdpNpTdFPgr9zkE=", "Subject": {"CommonName": "operator"}}

caller := {"Raw": "MIIBZjCCAQygAwIBAgIBBjAKBggqhkjOPQQDAjAUMRIwEAYDVQQDEwljYWxsZXItY2EwIBcNMjYwMTAxMDAwMDAwWhgPMjEyNjAxMDEwMDAwMDBaMBkxFzAVBgNVBAMTDmt1YmUtYXBpc2VydmVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEm/RleCzEmzrRZEPm+bI28hphbjJRkFvPXSX+RRWPn1drtRgsOYtA8Ryq2QbDSJWcZHJCSRTXQh5v/N3TZ5G7x6NIMEYwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFBasQM3T16Rq86787G/bFTLZxeJZMAoGCCqGSM49BAMCA0gAMEUCIQC9Otb+Oj5yPAHikgU9fE/TrH6usaaIB7MTdyDdJemG3gIgfPm06BTCMkZobRo+GC4HC8JXoIIRZW/2R5h10qO6ttk=", "Subject": {"CommonName": "kube-apiserver"}}

bootstrap := {
	"serviceUID": "service",
	"evaluatorID": "evaluator",
	"management": {"roots": [management_root], "identity": "operator"},
}

state := {
	"serviceUID": "service",
	"evaluatorID": "evaluator",
	"revision": "sha256:1",
	"endpoints": {"cluster": {"callers": ["kube-apiserver"]}},
}

state_paths := [
	["v1", "data", "authz", "state"],
	["v1", "data", "authz", "evaluator", "installed"],
]

state_path := ["v1", "data", "authz", "state"]

conditions_path := ["v1", "policies", "k8s-authz", "conditions"]

webhook_request(certificate) := {
	"method": "POST",
	"path": ["v0", "data", "authz", "endpoints", "cluster", "decision"],
	"params": {},
	"client_certificates": [certificate],
}

management_request(method, path, certificate) := {
	"method": method,
	"path": path,
	"params": {},
	"client_certificates": [certificate],
}

test_webhook_caller_listed_in_state_is_allowed if {
	authz.allow with input as webhook_request(caller) with data.bootstrap as bootstrap with data.authz.state as state
}

test_webhook_caller_with_parameters_is_allowed if {
	request := object.union(webhook_request(caller), {"params": {"timeout": ["10s"]}})
	authz.allow with input as request with data.bootstrap as bootstrap with data.authz.state as state
}

test_webhook_caller_not_listed_is_refused if {
	not authz.allow with input as webhook_request(operator) with data.bootstrap as bootstrap with data.authz.state as state
}

test_webhook_caller_is_refused_without_state if {
	not authz.allow with input as webhook_request(caller) with data.bootstrap as bootstrap
}

test_webhook_caller_is_refused_on_an_unknown_endpoint if {
	request := object.union(webhook_request(caller), {"path": ["v0", "data", "authz", "endpoints", "other", "decision"]})
	not authz.allow with input as request with data.bootstrap as bootstrap with data.authz.state as state
}

test_webhook_caller_is_refused_on_the_management_paths if {
	every path in state_paths {
		not authz.allow with input as management_request("GET", path, caller)
			with data.bootstrap as bootstrap
			with data.authz.state as state
	}
	every path in [state_path, conditions_path] {
		not authz.allow with input as management_request("PUT", path, caller)
			with data.bootstrap as bootstrap
			with data.authz.state as state
	}
}

test_management_caller_reads_state if {
	every path in state_paths {
		authz.allow with input as management_request("GET", path, operator) with data.bootstrap as bootstrap
	}
}

test_management_caller_replaces_state if {
	authz.allow with input as management_request("PUT", state_path, operator) with data.bootstrap as bootstrap
}

test_management_caller_replaces_the_conditions_module if {
	authz.allow with input as management_request("PUT", conditions_path, operator) with data.bootstrap as bootstrap
}

test_management_identity_from_another_ca_is_refused if {
	not authz.allow with input as management_request("PUT", state_path, caller_ca_operator_name)
		with data.bootstrap as bootstrap
}

test_management_ca_certificate_with_another_name_is_refused if {
	not authz.allow with input as management_request("PUT", state_path, management_ca_other_name)
		with data.bootstrap as bootstrap
}

test_management_caller_is_refused_elsewhere if {
	every request in [
		management_request("GET", ["v1", "policies"], operator),
		management_request("GET", ["v1", "data"], operator),
		management_request("PUT", ["v1", "data", "bootstrap"], operator),
		management_request("DELETE", ["v1", "data", "authz", "state"], operator),
		management_request("GET", ["v1", "data", "authz", "state", "revision"], operator),
		management_request("GET", conditions_path, operator),
		management_request("DELETE", conditions_path, operator),
		management_request("PUT", ["v1", "policies", "k8s-authz", "other"], operator),
		management_request("PUT", ["v1", "policies", "authz.rego"], operator),
	] {
		not authz.allow with input as request with data.bootstrap as bootstrap
	}
}

test_health_is_served if {
	every path in [["health", "live"], ["health", "ready"], ["metrics"]] {
		authz.allow with input as {"method": "GET", "path": path, "params": {}}
	}
}
