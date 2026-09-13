# Conditional delegation for application automation

This single-cluster example lets an application team manage permissions for its users and deployment automation while the platform retains control of their maximum scope. The team deliberately assigns broad permissions; an inherited platform policy limits them to selected resources in `team-a`, permits writes only on weekdays from 13:00 until 17:00 UTC, and prohibits deletion of the `database-data` PersistentVolumeClaim. Reads remain available throughout the week.

The write window is a Rego condition on the platform's delegation bound. It demonstrates how a team can change its own policy without removing an inherited condition or expanding the resources its automation may manage.

## What's in it

| File | Contents |
| --- | --- |
| `namespaces.yaml` | The control namespace `authz-system`, the platform's `platform-policies`, and the application's `team-a`. |
| `identities.yaml` | The deployment ServiceAccount `team-a/deployer`. |
| `sources.yaml` | Two local PolicySources with separate platform and team collections, both permitting Rego conditions. |
| `service.yaml` | The `application-authz` AuthorizationService and its `cluster` endpoint. |
| `platform.yaml` | The entry binding, root PolicySet, protected-storage prohibition, discovery permissions, and conditional delegation bound. |
| `teams.yaml` | The team's PolicySet and a deliberately broad permission assignment. |
| `writers.yaml` | Native RBAC allowing a separate group to edit the team's policy documents. |
| `requests/` | SubjectAccessReviews for checking reads, writes, the protected claim, and the namespace boundary. |

`kustomization.yaml` applies the resources together. The access reviews are separate: they ask permission questions without creating, modifying, or deleting the resources they describe. No workloads, storage, or GitOps reconciler are required to run those checks.

## How it's put together

The platform source collects only policy documents in `platform-policies`; the team source collects only policy documents in `team-a`. The authority selects `system:serviceaccount:team-a:deployer` and members of `oidc:team-a-users`. Other identities receive NoOpinion and continue to the remaining authorizers.

The platform delegates to the team's `application` PolicySet with a bound that permits ordinary operations on Deployments, Services, ConfigMaps, and PersistentVolumeClaims in `team-a`, plus read access to Pods. The Rego condition further limits writes to the weekday window. The delegation permits no further delegation. Although the team's child Policy uses wildcards, it cannot exceed any of these inherited limits.

The root prohibition rejects deletion of `database-data`, including an unrestricted collection deletion that could contain it. Discovery and self-review permissions sit alongside the delegation, so they remain available outside the write window. For selected identities, `whenNoPolicyAllows: Deny` prevents a later RBAC permission from supplying access outside this policy. The webhook must precede RBAC for these restrictions to apply.

Policy-writing access is separate from application access. `writers.yaml` lets `oidc:team-a-policy-authors` manage Policies, PolicyBindings, and PolicySets only in `team-a`. Those authors must use identities outside the application authority, since an explicit Deny would otherwise block their native writer role. The deployment ServiceAccount and application users cannot edit policy through this example. Only the platform should be able to change the platform documents, source/service configuration, engine management credentials, or API server configuration.

## Local validation

Run the commands below from this directory with a current `k8s-authz` CLI. These checks need no cluster:

```sh
k8s-authz validate documents --source authz-system/platform platform.yaml
k8s-authz validate documents --source authz-system/teams teams.yaml writers.yaml
k8s-authz validate documents sources.yaml service.yaml
k8s-authz validate graph service.yaml \
  --source authz-system/platform=platform.yaml \
  --source authz-system/teams=teams.yaml \
  --rego-source authz-system/platform \
  --rego-source authz-system/teams
```

The writer RBAC objects are validated as documents but are not collected into the delegated graph. Document validation checks strict decoding and semantic rules; it does not exercise the CRDs' API-server validation. See [Validating and explaining](../../docs/guides/validating-and-explaining.md).

## Running it

1. Install the operator and CRDs using the [installation guide](../../docs/operations/installation.md), with permission to read the local policy documents. You also need control of the API server's authorization configuration. Create the example's namespaces:

   ```sh
   kubectl apply -f namespaces.yaml
   ```

2. Provide the three Secrets referenced by `service.yaml`, in `authz-system`:

   | Secret | Contents |
   | --- | --- |
   | `application-authz-serving-tls` | A `kubernetes.io/tls` serving certificate for `authz-application-authz.authz-system.svc`. |
   | `application-authz-serving-ca` | `ca.crt`: the CA that issued the serving certificate. |
   | `apiserver-client-ca` | `ca.crt`: the CA that issues the API server's client certificate. |

   Use a caller certificate whose Common Name is `kube-apiserver-authz`, or update `service.yaml` to match your caller. The [API server integration guide](../../docs/guides/connecting-api-servers.md#certificates) describes the certificate requirements. If using the example's human groups, configure your authentication provider to supply those group names; the manifests do not create OIDC users or memberships.

3. Apply the example and check its status:

   ```sh
   kubectl apply -k .
   kubectl -n authz-system get policysources,authorizationservices
   ```

   Wait for `Ready=True` and `PolicyHealthy=True` on `application-authz` before configuring the API server. If the policy is unhealthy, inspect the service's `status.issues`.

4. Choose a recovery identity with independent RBAC permissions, then render the caller configuration. Replace the listener address with one reachable from the API server, and `oidc:k8s-root-admins` with your recovery group:

   ```sh
   k8s-authz render-caller-config --service-file service.yaml --endpoint cluster \
     --webhook-server 'https://<listener-address>:443' \
     --caller-certificate /etc/kubernetes/authz/client.crt \
     --caller-key /etc/kubernetes/authz/client.key \
     --engine-ca /etc/kubernetes/authz/serving-ca.crt \
     --webhook-kubeconfig-path /etc/kubernetes/authz/webhook.kubeconfig \
     --recovery-group oidc:k8s-root-admins \
     --authorized-ttl=0 --unauthorized-ttl=0 \
     --output-dir rendered/
   ```

   Both caches are disabled so a cached decision cannot outlive the time condition. Review the generated configuration and install it using [Connecting API servers](../../docs/guides/connecting-api-servers.md#installing-it-on-kube-apiserver). Keep the webhook before Node and RBAC, and retain the recovery exclusions appropriate to your cluster. Do not exclude `team-a/deployer` or the whole `system:serviceaccounts` group, since that would bypass the example's restrictions on automation.

The ServiceAccount gets its application permissions from the webhook, without a native RoleBinding. To use it with a real deployment workflow, configure the controller to make application requests as `system:serviceaccount:team-a:deployer` and extend the platform bound only with the resources and subresources that workflow needs. The supplied bound grants neither Pod writes nor Secret access. Actions performed later by other controllers use those controllers' own identities and need their own appropriate limits.

## Checking decisions

Using an administrator identity allowed to create SubjectAccessReviews, submit the supplied requests through the API server:

```sh
for request in requests/*.json; do
  printf '%s: ' "$request"
  kubectl create -f "$request" -o jsonpath='{.status}{"\n"}'
done
```

Each review asks about the deployment ServiceAccount, regardless of which administrator submits it. The named Deployment and PVC do not have to exist. The time condition uses the engine's current time; a SAR cannot supply a different time.

| Review | Weekday, 13:00–17:00 UTC | Outside the window |
| --- | --- | --- |
| `read-deployment.json`: get a Deployment in `team-a` | Allow | Allow |
| `patch-deployment.json`: patch a Deployment in `team-a` | Allow | Deny |
| `delete-protected-pvc.json`: delete `team-a/database-data` | Deny | Deny |
| `patch-other-namespace.json`: patch a Deployment in `team-b` | Deny | Deny |

To see which permissions and restrictions contribute to a decision, inspect the installed policy with the CLI:

```sh
k8s-authz explain application-authz -n authz-system \
  --endpoint cluster --sar requests/delete-protected-pvc.json
```

For a delegation check, have a policy author narrow the child Policy in `teams.yaml` to read-only operations, wait for the new policy to be installed, and repeat the Deployment reviews. Reads should still succeed, while writes should be denied even inside the window. Restoring the wildcard child Policy restores only the permissions within the platform's bound; it does not permit another namespace or deletion of the protected claim.

These reviews test authorization. Admission can still reject an authorized write, and changes to policy do not terminate existing sessions or undo work already accepted.
