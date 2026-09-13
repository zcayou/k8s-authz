package authz.evaluator.installed

# installed is what the operator reads of a pod: its state's revision and its
# conditions module's digest, each empty when absent.

default revision := ""

revision := data.authz.state.revision

default conditions_digest := ""

conditions_digest := data.authz.conditions.digest
