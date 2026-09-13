# Getting started

This walkthrough runs k8s-authz end to end on a local [Kind](https://kind.sigs.k8s.io/) cluster. You'll install the operator, write a small delegated policy, run an `AuthorizationService`, point the cluster's own kube-apiserver at it, and watch it make decisions.

It takes about 20 minutes. Everything happens in one cluster: the operator, the engines, the policy source, and the API server being authorized.

## What you'll build

- A platform team that owns a root `PolicySet` for everyone in `demo:` groups. It prohibits reading Secrets in `kube-system` and delegates namespace `team-a` to team-a.
- Team-a, which grants its admins everything, and still gets only namespace `team-a`.
- An `AuthorizationService` whose endpoint the Kind API server calls ahead of Node and RBAC.

## Prerequisites

- A checkout of this repository, and the tools it builds with: Go, Docker with `buildx`, and `make`.
- `kind` and `kubectl`.

Run every command from the repository root, in one shell session: later steps use files and variables that earlier steps create.

## 1. Create a Kind cluster with a configurable authorizer

kube-apiserver reads its authorizers from an `AuthorizationConfiguration` file and rereads it while running. Create a directory on your machine to hold that file and mount it into the control-plane node under `/etc/kubernetes/pki`, which kubeadm already mounts into the API server's pod:

```sh
mkdir -p authz-demo/apiserver
cat > authz-demo/apiserver/authorization-config.yaml <<'EOF'
apiVersion: apiserver.config.k8s.io/v1
kind: AuthorizationConfiguration
authorizers:
  - type: Node
    name: node
  - type: RBAC
    name: rbac
EOF

cat > authz-demo/kind.yaml <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  serviceSubnet: 10.96.0.0/16
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: $PWD/authz-demo/apiserver
        containerPath: /etc/kubernetes/pki/authz
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            - name: authorization-config
              value: /etc/kubernetes/pki/authz/authorization-config.yaml
  - role: worker
EOF

kind create cluster --name authz-demo --config authz-demo/kind.yaml
```

The cluster starts with Node and RBAC only, the usual defaults.

## 2. Build and load the operator and CLI

```sh
make docker-build IMG=k8s-authz:dev
kind load docker-image k8s-authz:dev --name authz-demo
make build
```

`make build` puts the CLI at `bin/k8s-authz`.

## 3. Issue certificates

k8s-authz needs several certificates: one the operator uses to manage engines, one for its diagnostics endpoint, one the engines serve, and one kube-apiserver presents when it calls them. This walkthrough issues them with [cert-manager](https://cert-manager.io/); any PKI works.

```sh
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
kubectl -n cert-manager wait deployment --all --for=condition=Available --timeout=3m
kubectl create namespace k8s-authz-system
kubectl create namespace authz-system
```

Create three certificate authorities (management, engine serving, and API server callers) and the certificates they issue:

```sh
kubectl apply -f - <<'EOF'
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  namespace: cert-manager
  name: authz-management-ca
spec:
  isCA: true
  commonName: authz-management-ca
  secretName: authz-management-ca
  issuerRef: {kind: ClusterIssuer, name: selfsigned}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  namespace: cert-manager
  name: authz-serving-ca
spec:
  isCA: true
  commonName: authz-serving-ca
  secretName: authz-serving-ca
  issuerRef: {kind: ClusterIssuer, name: selfsigned}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  namespace: cert-manager
  name: authz-caller-ca
spec:
  isCA: true
  commonName: authz-caller-ca
  secretName: authz-caller-ca
  issuerRef: {kind: ClusterIssuer, name: selfsigned}
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: authz-management
spec:
  ca: {secretName: authz-management-ca}
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: authz-serving
spec:
  ca: {secretName: authz-serving-ca}
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: authz-caller
spec:
  ca: {secretName: authz-caller-ca}
---
# The operator's management identity.
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  namespace: k8s-authz-system
  name: management-client-cert
spec:
  commonName: k8s-authz-operator
  usages: [client auth, digital signature, key encipherment]
  secretName: management-client-cert
  issuerRef: {kind: ClusterIssuer, name: authz-management}
---
# The diagnostics endpoint. It's reached through a port-forward, so its names don't matter.
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  namespace: k8s-authz-system
  name: diagnostics-server-cert
spec:
  dnsNames: [k8s-authz-diagnostics]
  usages: [server auth, digital signature, key encipherment]
  secretName: diagnostics-server-cert
  issuerRef: {kind: ClusterIssuer, name: authz-management}
---
# The engines' serving certificate for the service "demo" in "authz-system".
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  namespace: authz-system
  name: demo-serving-tls
spec:
  dnsNames: [authz-demo.authz-system.svc]
  usages: [server auth, digital signature, key encipherment]
  secretName: demo-serving-tls
  issuerRef: {kind: ClusterIssuer, name: authz-serving}
---
# The client certificate kube-apiserver presents to the engines.
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  namespace: authz-system
  name: apiserver-caller
spec:
  commonName: kube-apiserver-authz
  usages: [client auth, digital signature, key encipherment]
  secretName: apiserver-caller
  issuerRef: {kind: ClusterIssuer, name: authz-caller}
EOF
kubectl wait certificates -A --all --for=condition=Ready --timeout=2m
```

The operator also needs the management CA on its own, in a Secret named `management-ca`:

```sh
kubectl -n k8s-authz-system get secret management-client-cert -o jsonpath='{.data.ca\.crt}' | base64 -d > authz-demo/management-ca.crt
kubectl -n k8s-authz-system create secret generic management-ca --from-file=ca.crt=authz-demo/management-ca.crt
```

## 4. Install the operator

```sh
make deploy IMG=k8s-authz:dev
kubectl -n k8s-authz-system rollout status deployment/k8s-authz-controller-manager
```

This installs the five CRDs, the operator's RBAC, and the operator itself in `k8s-authz-system`.

## 5. Write the policy

Create the namespaces the policy lives in, and team-a's namespace:

```sh
kubectl create namespace platform-policies
kubectl create namespace team-a
```

The **platform team's** documents, in `platform-policies`:

```sh
kubectl apply -f - <<'EOF'
# Who the authority governs: everyone in a demo: group. Its target is the root PolicySet.
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: platform-policies
  name: demo-users
spec:
  subjectMatch:
    requirements:
      - kind: Group
        operator: StartsWith
        names: ["demo:"]
  policyRef:
    kind: PolicySet
    name: root
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySet
metadata:
  namespace: platform-policies
  name: root
spec:
  bindingRefs:
    - name: team-a
  prohibitionRefs:
    - name: protect-system-secrets
---
# A prohibition: nobody the authority governs may read Secrets in kube-system.
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: platform-policies
  name: protect-system-secrets
spec:
  subjectMatch: {}
  policyRef:
    name: protect-system-secrets
---
apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: platform-policies
  name: protect-system-secrets
spec:
  include:
    - apiGroups: [""]
      resources: [secrets]
      verbs: [get, list, watch]
      namespaces: [kube-system]
---
# A delegation: team-a's PolicySet, bounded to namespace team-a.
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: platform-policies
  name: team-a
spec:
  subjectMatch: {}
  policyRef:
    kind: PolicySet
    namespace: team-a
    name: team-a
  constraints:
    policyRef:
      name: team-a-bound
    maxDepth: 0
---
apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: platform-policies
  name: team-a-bound
spec:
  include:
    - apiGroups: ["*"]
      resources: ["*"]
      verbs: ["*"]
      namespaces: [team-a]
EOF
```

**Team-a's** documents, in `team-a`. Team-a grants its admins everything; the platform's bound limits that to `team-a`:

```sh
kubectl apply -f - <<'EOF'
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySet
metadata:
  namespace: team-a
  name: team-a
spec:
  bindingRefs:
    - name: admins
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: team-a
  name: admins
spec:
  subjects:
    - kind: Group
      name: demo:team-a-admins
  policyRef:
    name: everything
---
apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: team-a
  name: everything
spec:
  include:
    - apiGroups: ["*"]
      resources: ["*"]
      verbs: ["*"]
EOF
```

## 6. Register the source and create the service

```sh
kubectl apply -f - <<'EOF'
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySource
metadata:
  namespace: authz-system
  name: platform
spec:
  provider:
    type: Kubernetes
  collection:
    - kinds: [Policy, PolicyBinding, PolicySet]
      namespaces: [platform-policies, team-a]
      names: ["*"]
---
apiVersion: authorization.zctx.io/v1alpha1
kind: AuthorizationService
metadata:
  namespace: authz-system
  name: demo
spec:
  program:
    type: Kubernetes
  runtime:
    type: Deployment
    deployment:
      replicas: 2
    minReadyReplicas: 1
  listener:
    spec:
      clusterIP: 10.96.0.11
  tls:
    server:
      secretRef:
        name: demo-serving-tls
      caRef:
        secretKeyRef: {name: demo-serving-tls, key: ca.crt}
    client:
      caRef:
        secretKeyRef: {name: apiserver-caller, key: ca.crt}
  endpoints:
    - name: cluster
      callers:
        - commonName: kube-apiserver-authz
      sourceRefs:
        - namespace: authz-system
          name: platform
      whenEvaluationFails: NoOpinion
      authorities:
        - bindingRef:
            sourceRef: {namespace: authz-system, name: platform}
            namespace: platform-policies
            name: demo-users
          whenNoPolicyAllows: NoOpinion
EOF
kubectl -n authz-system wait authorizationservice/demo --for=condition=Ready --timeout=3m
kubectl -n authz-system get policysources,authorizationservices
```

```
NAME                                                 SYNCHRONIZED   LASTADMITTED   AGE
policysource.authorization.zctx.io/platform          True           40s            41s

NAME                                                     READY   PREPARED   READYREPLICAS   CURRENTREPLICAS   DESIREDREVISION   AGE
authorizationservice.authorization.zctx.io/demo          True    True       2               2                 sha256:…          41s
```

`kubectl -n authz-system get authorizationservice demo -o yaml` shows one `NamespaceScopeConservative` warning in `status.issues`, about `team-a-bound`. It warns that the Policy would reach further than it reads if it were used as a prohibition; as a bound it's exactly what's intended, and `PolicyHealthy` stays `True`.

The listener reserves `10.96.0.11` so the API server can reach it at a fixed address. Both fallbacks are `NoOpinion`, so anything this policy doesn't decide still goes to RBAC; that keeps a walkthrough mistake from locking you out. [The policy model](concepts/policy-model.md#deny-and-noopinion) explains the choice.

## 7. Point kube-apiserver at the endpoint

Copy the API server's client certificate and the engines' CA into the mounted directory, then render the authorization configuration into it. Paths passed to `render-caller-config` are paths inside the control-plane node.

```sh
kubectl -n authz-system get secret apiserver-caller -o jsonpath='{.data.tls\.crt}' | base64 -d > authz-demo/apiserver/client.crt
kubectl -n authz-system get secret apiserver-caller -o jsonpath='{.data.tls\.key}' | base64 -d > authz-demo/apiserver/client.key
kubectl -n authz-system get secret demo-serving-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > authz-demo/apiserver/serving-ca.crt

bin/k8s-authz render-caller-config demo -n authz-system \
  --endpoint cluster \
  --webhook-server https://10.96.0.11:443 \
  --caller-certificate /etc/kubernetes/pki/authz/client.crt \
  --caller-key /etc/kubernetes/pki/authz/client.key \
  --engine-ca /etc/kubernetes/pki/authz/serving-ca.crt \
  --webhook-kubeconfig-path /etc/kubernetes/pki/authz/webhook.kubeconfig \
  --recovery-group system:masters \
  --recovery-group kubeadm:cluster-admins \
  --recovery-group system:nodes \
  --recovery-group system:serviceaccounts \
  --recovery-user system:kube-controller-manager \
  --recovery-user system:kube-scheduler \
  --authorized-ttl=0 --unauthorized-ttl=0 \
  --output-dir authz-demo/apiserver
```

The recovery identities keep the cluster's components, its service accounts, and you (Kind's admin is in `kubeadm:cluster-admins`) independent of the webhook. The zero TTLs turn off kube-apiserver's decision cache so you see policy changes immediately.

kube-apiserver picks up the new file within about a minute. Check which configuration it has loaded:

```sh
kubectl get --raw /metrics | grep apiserver_authorization_config_controller_last_config_info
```

## 8. Try it

Ask kube-apiserver what `alice`, a team-a admin, may do. `kubectl auth can-i` with impersonation runs the check through the full authorizer chain as that user:

```sh
as_alice="--as alice --as-group demo:team-a-admins"

kubectl auth can-i delete deployments -n team-a $as_alice    # yes: granted by team-a, within the bound
kubectl auth can-i delete deployments -n default $as_alice   # no: outside the bound, and RBAC grants nothing
kubectl auth can-i get secrets -n kube-system $as_alice      # no
```

Now give alice `cluster-admin` through ordinary RBAC:

```sh
kubectl create clusterrolebinding alice-admin --clusterrole=cluster-admin --user=alice

kubectl auth can-i delete deployments -n default $as_alice   # yes: the webhook has no opinion, RBAC allows
kubectl auth can-i get secrets -n default $as_alice          # yes
kubectl auth can-i get secrets -n kube-system $as_alice      # no: the root prohibition overrides RBAC
kubectl auth can-i list secrets -A $as_alice                 # no: an all-namespace list includes kube-system
```

The prohibition holds even for a cluster administrator, because the webhook runs first and answers Deny.

## 9. Explain a decision

`k8s-authz explain` evaluates a request against the policy an engine actually has installed, and shows which documents decided it:

```sh
cat > authz-demo/request.json <<'EOF'
{
  "apiVersion": "authorization.k8s.io/v1",
  "kind": "SubjectAccessReview",
  "spec": {
    "user": "alice",
    "groups": ["demo:team-a-admins", "system:authenticated"],
    "resourceAttributes": {"namespace": "kube-system", "verb": "get", "resource": "secrets"}
  }
}
EOF
bin/k8s-authz explain demo -n authz-system --endpoint cluster --sar authz-demo/request.json -o json
```

The report shows `result: Deny` with code `RootProhibited`, and its `prohibitions` list gives the path from the `demo-users` entry binding through the root `PolicySet` to the `protect-system-secrets` Policy.

## 10. Change policy live

Edit team-a's policy and watch the engines pick it up without restarting. Replace the `everything` Policy with a read-only one:

```sh
kubectl -n team-a patch policy everything --type merge -p '{"spec":{"include":[{"apiGroups":["*"],"resources":["*"],"verbs":["get","list","watch"]}]}}'
kubectl -n authz-system get authorizationservice demo -w
```

`DESIREDREVISION` changes within a few seconds, and `CURRENTREPLICAS` stays at 2: both engines receive the new revision by push, and neither pod restarts. Press Ctrl-C to stop watching. Then:

```sh
kubectl auth can-i delete deployments -n team-a --as alice --as-group demo:team-a-admins
```

still says `yes`, because alice's RBAC `cluster-admin` now answers after the webhook's NoOpinion. Delete the `alice-admin` ClusterRoleBinding and it says `no`.

## Clean up

```sh
kind delete cluster --name authz-demo
rm -rf authz-demo
```

## Next steps

- [Policy model](concepts/policy-model.md) and [Delegation](concepts/delegation.md) explain what you just built.
- [Writing policies](guides/writing-policies.md) covers the full permission language.
- [Connecting API servers](guides/connecting-api-servers.md) covers production caller setups, including remote API servers and several endpoints.
- The [local](../examples/local/README.md) and [hosted](../examples/hosted/README.md) examples show larger layouts, including native RBAC imports and a remote source.
