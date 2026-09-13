# Rego conditions

Most policy needs no code: operation rules, bindings, and bounds express it. When a grant depends on something they can't express, such as a relationship between the user's name and the request's namespace, a `Policy` can carry a **Rego condition** that narrows it further.

Conditions are off by default. A source's documents may carry them only if the `PolicySource` opts in.

## Writing a condition

A condition is a Rego v1 module in `spec.condition.rego`. It declares `package condition` and a rule `allow`. The Policy grants its operations only to requests for which `allow` is `true`:

```yaml
apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: team-policies
  name: own-namespace-deployments
spec:
  include:
    - apiGroups: [apps]
      resources: [deployments]
      verbs: [create, update, patch, delete]
  condition:
    rego: |
      package condition

      allow if {
        input.request.resourceAttributes.namespace == concat("-", ["team", input.principal.user])
      }
```

The rules a condition must follow:

- It declares `package condition` and defines `allow`, which must be `true` when it holds. It can also declare `default allow := false`, but no other default and no `else`.
- It may define helper rules and functions. Rule names must be plain (no reference heads such as `a.b.c if ...`), and a module may have at most 128 rules.
- It may import only `rego.v1` and `future.keywords`.
- It may not use `with`, and it may not reference `data` except its own rules.
- It may call only the builtins its path allows (see [Allowing builtins](#allowing-builtins)).

A condition that is false, undefined, or errors doesn't hold, so the grant it guards fails closed.

## The condition's input

```json
{
  "principal": {
    "user": "alice",
    "groups": ["oidc:team-alice", "system:authenticated"],
    "uid": "1f6e…",
    "extra": {"scopes": ["read"]}
  },
  "request": {
    "resourceAttributes": {
      "namespace": "team-alice",
      "verb": "create",
      "group": "apps",
      "version": "v1",
      "resource": "deployments",
      "subresource": "",
      "name": "",
      "fieldSelector": {},
      "labelSelector": {}
    }
  }
}
```

- `principal` is the principal as the endpoint received it: `groups` sorted and de-duplicated, and `extra` an object of sorted value lists, `{}` when absent.
- `request` holds exactly one of `resourceAttributes` or `nonResourceAttributes`. Resource attributes the request doesn't carry are `""`, and selectors are `{}`, or as kube-apiserver sent them. Non-resource requests carry `path` and `verb`.
- The request is kube-apiserver's view of it, not a normalized one. A list across all namespaces has `namespace: ""`.

## Where a condition applies

A condition narrows exactly the grants that pass through its Policy:

- **On a granted Policy**, the condition narrows that grant. With `include` or `imports`, the Policy grants its operations only where the condition holds. With neither, it grants any operation where the condition holds; the operator flags that with the `UniversalEnvelope` warning, because the condition then decides every request inside the Policy's bound. `include: []` still grants nothing.
- **On a bound** (a Policy used as `constraints.policyRef`), the condition narrows every grant beneath that binding, all the way down the delegation.

Conditions accumulate like principal matches: a grant applies only if its principals match every binding on its path and every condition on its path holds. The engine evaluates conditions only after the principal matches, so a condition never runs for principals its bindings don't select.

Prohibitions are decided without running conditions. A prohibition that would carry a condition, from its own Policy or from a bound above it, fails with `ConditionalProhibition`, and the endpoint answers matching requests with `whenEvaluationFails`.

## Enabling conditions on a source

A `PolicySource` allows conditions with `rego`:

```yaml
kind: PolicySource
spec:
  rego: {}                           # the release's default builtins
```

```yaml
spec:
  rego:
    allowedBuiltins: [concat, startswith, regex.match]   # exactly these
```

A source without `rego` admits no conditions, either in its own Policies or anywhere beneath its bindings and `PolicySet`s. This setting belongs to whoever registers the source, never to the documents' authors, and changing it recompiles the affected services without restarting the source's reader.

### Allowing builtins

A condition may call a builtin only if every layer above it allows that builtin:

1. The Policy's own source must allow it.
2. Every binding and `PolicySet` on the path from the authority's root down to the use comes from some source, and each of those sources must allow it too. A source on the path without `rego` forbids conditions below it entirely (`RegoNotAllowed`).
3. The `AuthorizationService`'s `spec.rego.allowedBuiltins`, if set, caps every condition the service compiles, because conditions run in its engines. `allowedBuiltins: []` admits only conditions that call no builtins.

Only delegation narrows. The Policies a use reaches, and the native roles they import, don't. A native RBAC source never blocks a condition on a Policy that imports its roles, and a delegated source's allowlist doesn't reject a condition an ancestor attached through a bound.

A condition that calls a builtin its path doesn't allow fails with `BuiltinNotAllowed`, naming the builtins. The failure follows the usual rule: on a grant, that grant is dropped.

The **default builtins** are the pure builtins whose cost the condition's input bounds: string, regex, glob, array, object, JSON/YAML, encoding, hashing, `semver`, `time`, `units`, CIDR matching, and bitwise functions. They exclude network access (`http.send`, `net.lookup_ip_addr`), runtime and environment access (`opa.runtime`), randomness, `print` and `trace`, `rego.*`, certificate, key, and JWT functions, and every builtin a constant can make run for unbounded time (`numbers.range`, `numbers.range_step`, `net.cidr_expand`, `bits.lsh`, `strings.render_template`). An `allowedBuiltins` list replaces the default entirely.

## Risks

Conditions run inside the engines that serve every principal of the service, and the operator's checks are their only gate: stock OPA can't restrict the builtins of a module pushed through its API. The narrowing rules keep authorization sound, since a condition can only remove access. What a condition can affect is availability:

- A conflict in a helper rule's outputs, or an object built with duplicate keys, aborts the whole evaluation. The engine answers with an HTTP error, and kube-apiserver applies the webhook's `failurePolicy`. Only requests inside the Policy's operations, from principals its bindings match, reach the condition.
- OPA has no per-query CPU budget. A slow condition keeps using CPU after the webhook call times out and can starve its engine, health probes included. The default builtins leave out every builtin known to run unbounded on a constant; a source that allows more accepts that cost.
- Builtins beyond the default carry their own risk. Network builtins make decisions depend on external services and let condition authors reach anything the engine pods can reach. `opa.runtime` exposes the engines' environment and configuration. `print` writes to the engine logs. Use the service's `rego.allowedBuiltins` to refuse them for its engines.
- The operator's management credential can install Rego in the engines, not just data. Protect it accordingly.

## How conditions reach the engines

The operator generates one conditions module from every condition a service's policy uses, and installs it on each engine before the state that refers to it. Condition edits are pushed without restarting the engines. While a push is between the two writes, grants whose conditions only the previous state carries fail closed.

A service's conditions module is limited to 1 MiB, and its state to 32 MiB. Exceeding either fails compilation.

## Testing conditions

A condition is ordinary Rego, so you can test it locally with `opa eval` and `opa test` under `package condition`:

```rego
package condition_test

import data.condition

test_own_namespace if {
  condition.allow with input as {
    "principal": {"user": "alice", "groups": [], "uid": "", "extra": {}},
    "request": {"resourceAttributes": {"namespace": "team-alice", "verb": "create"}},
  }
}
```

To check it in context, including the builtin allowlists, compile the service offline and mark the sources that allow conditions. A team's condition reached through the platform's bindings needs both sources to allow it:

```sh
k8s-authz validate graph service.yaml \
  --source authz-system/platform=platform.yaml \
  --source authz-system/teams=teams.yaml \
  --rego-source authz-system/platform \
  --rego-source authz-system/teams=concat,startswith
```

`--rego-source NAMESPACE/NAME` allows the default builtins, and `NAMESPACE/NAME=BUILTIN,...` allows exactly the builtins listed, as the `PolicySource`'s `rego` field does.

`k8s-authz explain` reports whether each condition on the path of a decision held, though not why. See [Validating and explaining](validating-and-explaining.md).
