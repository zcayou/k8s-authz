group "default" {
  targets = ["k8s-authz", "k8s-authz-cli"]
}

target "k8s-authz" {
  inherits = ["_common"]
  target   = "manager"
  tags     = tags("k8s-authz")
}

target "k8s-authz-cli" {
  inherits = ["_common"]
  target   = "cli"
  tags     = tags("k8s-authz-cli")
}
