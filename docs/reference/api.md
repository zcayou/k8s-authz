# API Reference

## Packages
- [authorization.zctx.io/v1alpha1](#authorizationzctxiov1alpha1)


## authorization.zctx.io/v1alpha1

Package v1alpha1 contains API Schema definitions for the authorization
v1alpha1 API group.

### Resource Types
- [AuthorizationService](#authorizationservice)
- [Policy](#policy)
- [PolicyBinding](#policybinding)
- [PolicySet](#policyset)
- [PolicySource](#policysource)



#### Authority



Authority attaches a binding with an explicit uncovered-request fallback.



_Appears in:_
- [Endpoint](#endpoint)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `bindingRef` _[BindingRef](#bindingref)_ | bindingRef identifies the principal-to-policy association. It names its<br />PolicySource explicitly. |  | Required: \{\} <br /> |
| `whenNoPolicyAllows` _[DecisionFallback](#decisionfallback)_ | whenNoPolicyAllows is the fallback after selecting this binding. It also<br />applies when an Allow can't be resolved, because a broken Allow grants<br />nothing; the problem is reported in status. |  | Enum: [Deny NoOpinion] <br />Required: \{\} <br /> |


#### AuthorizationProgram



AuthorizationProgram selects the built-in request integration.



_Appears in:_
- [AuthorizationServiceSpec](#authorizationservicespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `type` _[ProgramType](#programtype)_ | type selects the request and response contract. |  | Enum: [Kubernetes] <br />Required: \{\} <br /> |


#### AuthorizationService



AuthorizationService owns a serving group and its authorization endpoints.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.zctx.io/v1alpha1` | | |
| `kind` _string_ | `AuthorizationService` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  | Optional: \{\} <br /> |
| `spec` _[AuthorizationServiceSpec](#authorizationservicespec)_ | spec defines the serving group and authorization roots. |  | Required: \{\} <br /> |
| `status` _[AuthorizationServiceStatus](#authorizationservicestatus)_ | status reports observed preparation and serving state. |  | Optional: \{\} <br /> |


#### AuthorizationServiceRego



AuthorizationServiceRego limits the builtins Rego conditions may call
in the service's engines.



_Appears in:_
- [AuthorizationServiceSpec](#authorizationservicespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowedBuiltins` _string array_ | allowedBuiltins caps every source's allowed builtins. |  | MaxItems: 256 <br />items:MaxLength: 128 <br />items:MinLength: 1 <br />Required: \{\} <br /> |


#### AuthorizationServiceRuntime



AuthorizationServiceRuntime configures the managed serving workload.



_Appears in:_
- [AuthorizationServiceSpec](#authorizationservicespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `type` _[RuntimeType](#runtimetype)_ | type selects the workload kind. |  | Enum: [Deployment DaemonSet] <br />Required: \{\} <br /> |
| `deployment` _[DeploymentRuntime](#deploymentruntime)_ | deployment configures the Deployment, used only when type is Deployment. | \{  \} | Optional: \{\} <br /> |
| `minReadyReplicas` _integer_ | minReadyReplicas is the ready engine count the service keeps through<br />rollouts, voluntary disruptions and runtime-kind switches. Equal<br />to deployment.replicas, it lets no ready engine Pod be evicted, which blocks<br />node drains. | 1 | Minimum: 1 <br />Optional: \{\} <br /> |
| `metadata` _[ResourceMetadata](#resourcemetadata)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  | Optional: \{\} <br /> |
| `podTemplate` _[PodTemplateOverride](#podtemplateoverride)_ | podTemplate customizes the generated engine Pods. |  | Optional: \{\} <br /> |


#### AuthorizationServiceSpec



AuthorizationServiceSpec defines one serving group and its endpoint contracts.



_Appears in:_
- [AuthorizationService](#authorizationservice)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `program` _[AuthorizationProgram](#authorizationprogram)_ | program selects the request integration for every endpoint. |  | Required: \{\} <br /> |
| `runtime` _[AuthorizationServiceRuntime](#authorizationserviceruntime)_ | runtime selects the managed serving workload and its capacity. |  | Required: \{\} <br /> |
| `listener` _[ServiceTemplateOverride](#servicetemplateoverride)_ | listener customizes the generated listener Service. |  | Optional: \{\} <br /> |
| `tls` _[AuthorizationServiceTLS](#authorizationservicetls)_ | tls configures the engines' serving identity and their callers' CA. |  | Required: \{\} <br /> |
| `endpoints` _[Endpoint](#endpoint) array_ | endpoints contains the service's authenticated decision routes. |  | MaxItems: 16 <br />MinItems: 1 <br />Required: \{\} <br /> |
| `rego` _[AuthorizationServiceRego](#authorizationservicerego)_ | rego caps the builtins Rego conditions may call in this service's engines.<br />Omission imposes no limit beyond the sources'. |  | Optional: \{\} <br /> |


#### AuthorizationServiceStatus



AuthorizationServiceStatus reports preparation and serving state.



_Appears in:_
- [AuthorizationService](#authorizationservice)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | observedGeneration is the spec generation this status reports on. |  | Optional: \{\} <br /> |
| `desiredRevision` _string_ | desiredRevision is the content-addressed revision of the policy snapshot<br />prepared for the current spec and sources. |  | Optional: \{\} <br /> |
| `desiredReplicas` _integer_ | desiredReplicas is the number of engine Pods the workload is expected<br />to run. It is absent while a DaemonSet has not reported its scheduled count. |  | Optional: \{\} <br /> |
| `readyReplicas` _integer_ | readyReplicas is the number of ready engine Pods, each serving the state<br />installed on it. |  | Optional: \{\} <br /> |
| `currentReplicas` _integer_ | currentReplicas is the number of engine Pods serving desiredRevision<br />that started from the current engine startup configuration. |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#condition-v1-meta) array_ | conditions are Prepared, Ready and PolicyHealthy. |  | Optional: \{\} <br /> |
| `issues` _[Issue](#issue) array_ | issues contains bounded attributed diagnostics for the service<br />and the policy it compiles. |  | MaxItems: 128 <br />Optional: \{\} <br /> |
| `issuesTruncated` _boolean_ | issuesTruncated reports that additional diagnostics were omitted. |  | Optional: \{\} <br /> |


#### AuthorizationServiceTLS



AuthorizationServiceTLS configures the engines' serving identity and the CA
that issues their webhook callers' certificates.



_Appears in:_
- [AuthorizationServiceSpec](#authorizationservicespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `server` _[ServerTLS](#servertls)_ | server identifies the engines' serving certificate and its CA. |  | Required: \{\} <br /> |
| `client` _[ClientTLS](#clienttls)_ | client identifies the CA that issues the certificates of every endpoint's<br />callers. |  | Required: \{\} <br /> |


#### BindingConstraints



BindingConstraints restricts one policy association.



_Appears in:_
- [PolicyBindingSpec](#policybindingspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `policyRef` _[PolicyRef](#policyref)_ | policyRef supplies a leaf permission bound. |  | Optional: \{\} <br /> |
| `sourceRefs` _[SourceRef](#sourceref) array_ | sourceRefs narrows the incoming sources for a PolicySet target. It must<br />include the target's own source. |  | MaxItems: 64 <br />MinItems: 1 <br />Optional: \{\} <br /> |
| `maxDepth` _integer_ | maxDepth caps further PolicySet edges below the target. |  | Maximum: 64 <br />Minimum: 0 <br />Optional: \{\} <br /> |


#### BindingRef



BindingRef identifies a custom PolicyBinding or native RBAC binding.



_Appears in:_
- [Authority](#authority)
- [PolicySetSpec](#policysetspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiGroup` _string_ | apiGroup is the referenced kind's API group. It is derived from kind when<br />omitted. |  | MaxLength: 253 <br />Optional: \{\} <br /> |
| `kind` _string_ | kind is PolicyBinding, RoleBinding, or ClusterRoleBinding. Omission means<br />PolicyBinding. |  | Enum: [PolicyBinding RoleBinding ClusterRoleBinding] <br />Optional: \{\} <br /> |
| `name` _string_ | name is the binding name. |  | MaxLength: 253 <br />MinLength: 1 <br />Required: \{\} <br /> |
| `namespace` _string_ | namespace is the logical namespace of a namespaced binding. Omission<br />means the referencing document's namespace. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br />Optional: \{\} <br /> |
| `sourceRef` _[SourceRef](#sourceref)_ | sourceRef selects another allowed PolicySource. |  | Optional: \{\} <br /> |


#### CABundleRef



CABundleRef identifies a PEM CA bundle held in a key of a Secret
or a ConfigMap in the AuthorizationService's namespace.



_Appears in:_
- [ClientTLS](#clienttls)
- [ServerTLS](#servertls)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `secretKeyRef` _[SecretKeyRef](#secretkeyref)_ | secretKeyRef selects a Secret key. |  | Optional: \{\} <br /> |
| `configMapKeyRef` _[ConfigMapKeyRef](#configmapkeyref)_ | configMapKeyRef selects a ConfigMap key. |  | Optional: \{\} <br /> |


#### Caller



Caller admits one webhook client by its certificate subject,
as kube-apiserver identifies x509 clients.



_Appears in:_
- [Endpoint](#endpoint)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `commonName` _string_ | commonName is the subject Common Name of the caller's client certificate.<br />Renewing or re-keying the certificate needs no change here. |  | MaxLength: 64 <br />MinLength: 1 <br />Required: \{\} <br /> |


#### ClientTLS



ClientTLS configures the CA the engines verify webhook callers' client
certificates with. Each endpoint then admits its callers by Common Name,
as kube-apiserver identifies x509 clients against one client CA.



_Appears in:_
- [AuthorizationServiceTLS](#authorizationservicetls)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `caRef` _[CABundleRef](#cabundleref)_ | caRef identifies the CA bundle that issues the callers' client certificates.<br />The engines reload it in place, so changing its content never restarts<br />them. |  | Required: \{\} <br /> |


#### ConfigMapKeyRef



ConfigMapKeyRef identifies a key in a ConfigMap in the containing control
resource's namespace.



_Appears in:_
- [CABundleRef](#cabundleref)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | name is the ConfigMap name. |  | MaxLength: 253 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$` <br />Required: \{\} <br /> |
| `key` _string_ | key is the ConfigMap data key. |  | MaxLength: 253 <br />MinLength: 1 <br />Pattern: `^[-._a-zA-Z0-9]+$` <br />Required: \{\} <br /> |


#### Contribution

_Underlying type:_ _string_

Contribution selects whether a PolicySource's documents take part in compiled
policy. Inert removes them: references into the source then fail
as references into an unavailable source, whose issue names Inert.

_Validation:_
- Enum: [Active Inert]

_Appears in:_
- [PolicySourceSpec](#policysourcespec)

| Field | Description |
| --- | --- |
| `Active` | ContributionActive includes the source's documents in compiled policy.<br /> |
| `Inert` | ContributionInert leaves the source's documents out of compiled policy.<br /> |


#### DecisionFallback

_Underlying type:_ _string_

DecisionFallback is the result returned when policy doesn't decide a request.
Deny is an authoritative denial, and NoOpinion defers to the caller's next
authorizer.

_Validation:_
- Enum: [Deny NoOpinion]

_Appears in:_
- [Authority](#authority)
- [Endpoint](#endpoint)

| Field | Description |
| --- | --- |
| `Deny` | DecisionFallbackDeny denies the request authoritatively.<br /> |
| `NoOpinion` | DecisionFallbackNoOpinion defers the request to the next authorizer.<br /> |


#### DeploymentRuntime



DeploymentRuntime configures the engine Deployment.



_Appears in:_
- [AuthorizationServiceRuntime](#authorizationserviceruntime)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `replicas` _integer_ | replicas is the number of engine Pods. | 2 | Minimum: 1 <br />Optional: \{\} <br /> |


#### Endpoint



Endpoint defines an authenticated SubjectAccessReview decision route.



_Appears in:_
- [AuthorizationServiceSpec](#authorizationservicespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | name is the DNS-1035 route key. |  | MaxLength: 63 <br />Pattern: `^[a-z]([-a-z0-9]*[a-z0-9])?$` <br />Required: \{\} <br /> |
| `callers` _[Caller](#caller) array_ | callers contains clients admitted to this route, whose certificates<br />the service's client CA issues. Editing them takes effect without restarting<br />the engines. |  | MaxItems: 16 <br />MinItems: 1 <br />Required: \{\} <br /> |
| `sourceRefs` _[SourceRef](#sourceref) array_ | sourceRefs is the complete source set available to authority roots. |  | MaxItems: 64 <br />MinItems: 1 <br />Required: \{\} <br /> |
| `authorities` _[Authority](#authority) array_ | authorities is evaluated in order and may be explicitly empty. |  | MaxItems: 64 <br />Required: \{\} <br /> |
| `whenEvaluationFails` _[DecisionFallback](#decisionfallback)_ | whenEvaluationFails is the result when this endpoint can't evaluate<br />a request: the SubjectAccessReview is malformed, the engine has no policy<br />state, the selected entry binding can't be resolved, or a prohibition can't<br />be resolved. Deny responds with denied=true and NoOpinion with allowed=false<br />and denied=false; both carry evaluationError. The caller configuration<br />rendered by k8s-authz sets the webhook failurePolicy to the value it has<br />when rendered, so an engine that can't answer at all behaves the same way;<br />render the caller configuration again after changing it. kube-apiserver<br />caches these responses for unauthorizedTTL when it caches unauthorized<br />decisions. |  | Enum: [Deny NoOpinion] <br />Required: \{\} <br /> |


#### FieldSelector



FieldSelector restricts a collection operation with parsed field requirements.



_Appears in:_
- [OperationRule](#operationrule)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `requirements` _[FieldSelectorRequirement](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#fieldselectorrequirement-v1-meta) array_ | requirements are ANDed parsed field selector requirements. |  | MaxItems: 64 <br />Optional: \{\} <br /> |


#### Issue



Issue is a bounded diagnostic projected into control-resource status.



_Appears in:_
- [AuthorizationServiceStatus](#authorizationservicestatus)
- [PolicySourceStatus](#policysourcestatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `severity` _[IssueSeverity](#issueseverity)_ | severity is Error or Warning. |  | Enum: [Error Warning] <br /> |
| `reason` _string_ | reason is a stable machine-readable reason. |  |  |
| `message` _string_ | message is a human-readable diagnostic. |  |  |
| `scope` _[IssueScope](#issuescope)_ | scope identifies the diagnostic attribution level. |  | Enum: [Document Use] <br /> |
| `sourceRef` _[SourceRef](#sourceref)_ | sourceRef identifies the source of the affected document when known. |  |  |
| `documentRef` _[QualifiedDocumentRef](#qualifieddocumentref)_ | documentRef identifies an affected document when known. |  |  |
| `endpoint` _string_ | endpoint identifies an affected endpoint when known. |  |  |
| `authority` _string_ | authority identifies an affected authority when known. |  |  |
| `contextID` _string_ | contextID identifies one contextual graph use when known. |  |  |
| `path` _[QualifiedDocumentRef](#qualifieddocumentref) array_ | path is the ordered qualified ancestry for a contextual use. |  |  |


#### IssueScope

_Underlying type:_ _string_

IssueScope identifies the level to which a diagnostic is attributed.

_Validation:_
- Enum: [Document Use]

_Appears in:_
- [Issue](#issue)

| Field | Description |
| --- | --- |
| `Document` | IssueScopeDocument attributes a diagnostic to a canonical document.<br /> |
| `Use` | IssueScopeUse attributes a diagnostic to one contextual document use.<br /> |


#### IssueSeverity

_Underlying type:_ _string_

IssueSeverity classifies a diagnostic as an error or warning.

_Validation:_
- Enum: [Error Warning]

_Appears in:_
- [Issue](#issue)

| Field | Description |
| --- | --- |
| `Error` | IssueSeverityError identifies a diagnostic affecting validity or evaluation.<br /> |
| `Warning` | IssueSeverityWarning identifies an advisory diagnostic.<br /> |


#### KeyRange



KeyRange selects policy documents to collect from a source. Cluster-scoped
kinds omit namespaces; every other kind requires them.



_Appears in:_
- [PolicySourceSpec](#policysourcespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `kinds` _string array_ | kinds are the canonical kinds included in the range. |  | MaxItems: 256 <br />MinItems: 1 <br />items:Enum: [Policy PolicyBinding PolicySet Role ClusterRole RoleBinding ClusterRoleBinding] <br />Required: \{\} <br /> |
| `namespaces` _string array_ | namespaces are the logical namespaces included in the range. "*" selects<br />every namespace. |  | MaxItems: 256 <br />MinItems: 1 <br />items:MaxLength: 63 <br />items:Pattern: `^(\*\|[a-z0-9]([-a-z0-9]*[a-z0-9])?)$` <br />Optional: \{\} <br /> |
| `names` _string array_ | names are the document names included in the range. "*" selects every<br />name. |  | MaxItems: 256 <br />MinItems: 1 <br />items:MaxLength: 253 <br />items:MinLength: 1 <br />Required: \{\} <br /> |


#### KubeconfigReference



KubeconfigReference identifies a kubeconfig stored in a Secret.



_Appears in:_
- [KubernetesProvider](#kubernetesprovider)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `secretRef` _[SecretKeyRef](#secretkeyref)_ | secretRef identifies the Secret data containing the kubeconfig. |  | Required: \{\} <br /> |


#### KubernetesProvider



KubernetesProvider configures acquisition from a Kubernetes API.



_Appears in:_
- [PolicySourceProvider](#policysourceprovider)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `kubeconfig` _[KubeconfigReference](#kubeconfigreference)_ | kubeconfig selects an explicit kubeconfig credential. Omission reads<br />from the operator's own cluster with the operator's credentials. |  | Optional: \{\} <br /> |


#### NamespaceLabels

_Underlying type:_ _string_

NamespaceLabels selects whether a PolicySource reads the labels
of the namespaces its collection covers.

_Validation:_
- Enum: [Collect Ignore]

_Appears in:_
- [PolicySourceSpec](#policysourcespec)

| Field | Description |
| --- | --- |
| `Collect` | NamespaceLabelsCollect reads the labels of the collected namespaces.<br /> |
| `Ignore` | NamespaceLabelsIgnore reads no namespace labels.<br /> |


#### OperationRule



OperationRule describes a complete resource or non-resource operation set.



_Appears in:_
- [PolicySpec](#policyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `verbs` _string array_ | verbs are Kubernetes resource verbs or lowercase HTTP verbs. |  | MaxItems: 256 <br />MinItems: 1 <br />Required: \{\} <br /> |
| `apiGroups` _string array_ | apiGroups are the resource API groups. |  | MaxItems: 256 <br />MinItems: 1 <br />Optional: \{\} <br /> |
| `resources` _string array_ | resources are resource or resource/subresource names. |  | MaxItems: 256 <br />MinItems: 1 <br />Optional: \{\} <br /> |
| `apiVersions` _string array_ | apiVersions are resource API versions. Omission means every version. |  | MaxItems: 256 <br />MinItems: 1 <br />Optional: \{\} <br /> |
| `resourceNames` _string array_ | resourceNames restrict resource operations to exact names. |  | MaxItems: 256 <br />Optional: \{\} <br /> |
| `namespaces` _string array_ | namespaces restrict resource operations by request effect namespace.<br />"*" matches every named namespace, and "" matches requests without one. |  | MaxItems: 256 <br />MinItems: 1 <br />items:MaxLength: 63 <br />items:Pattern: `^(\*\|[a-z0-9]([-a-z0-9]*[a-z0-9])?)?$` <br />Optional: \{\} <br /> |
| `nonResourceURLs` _string array_ | nonResourceURLs are exact or suffix-wildcard absolute paths. |  | MaxItems: 256 <br />MinItems: 1 <br />Optional: \{\} <br /> |
| `labelSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#labelselector-v1-meta)_ | labelSelector restricts collection members with a native label selector. |  | Optional: \{\} <br /> |
| `fieldSelector` _[FieldSelector](#fieldselector)_ | fieldSelector restricts collection members with parsed field requirements. |  | Optional: \{\} <br /> |


#### PodSpecOverride



PodSpecOverride contains the Pod spec fields an AuthorizationService can
customize. Named lists merge with the operator's entries by name.



_Appears in:_
- [PodTemplateOverride](#podtemplateoverride)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `containers` _[Container](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#container-v1-core) array_ | containers merge with the operator's containers by name. The engine<br />container is named opa. |  | Optional: \{\} <br /> |
| `initContainers` _[Container](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#container-v1-core) array_ | initContainers are added to the engine Pods. |  | Optional: \{\} <br /> |
| `volumes` _[Volume](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#volume-v1-core) array_ | volumes merge with the operator's volumes by name. |  | Optional: \{\} <br /> |
| `imagePullSecrets` _[LocalObjectReference](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#localobjectreference-v1-core) array_ | imagePullSecrets are used to pull the engine and any added container images. |  | Optional: \{\} <br /> |
| `nodeSelector` _object (keys:string, values:string)_ | nodeSelector constrains the nodes that run engine Pods. |  | Optional: \{\} <br /> |
| `serviceAccountName` _string_ | serviceAccountName runs the engine Pods under this ServiceAccount instead<br />of the namespace's default one. The engines never mount its token. |  | Optional: \{\} <br /> |
| `securityContext` _[PodSecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#podsecuritycontext-v1-core)_ | securityContext replaces fields of the operator's Pod security context. |  | Optional: \{\} <br /> |
| `affinity` _[Affinity](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#affinity-v1-core)_ | affinity sets the Pods' scheduling affinity. |  | Optional: \{\} <br /> |
| `tolerations` _[Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#toleration-v1-core) array_ | tolerations let engine Pods schedule onto tainted nodes. |  | Optional: \{\} <br /> |
| `priorityClassName` _string_ | priorityClassName sets the Pods' priority class. |  | Optional: \{\} <br /> |
| `terminationGracePeriodSeconds` _integer_ | terminationGracePeriodSeconds sets the Pods' termination grace period. |  | Optional: \{\} <br /> |
| `hostNetwork` _boolean_ | hostNetwork runs the Pods in the host's network namespace. |  | Optional: \{\} <br /> |
| `hostPID` _boolean_ | hostPID runs the Pods in the host's PID namespace. |  | Optional: \{\} <br /> |
| `hostIPC` _boolean_ | hostIPC runs the Pods in the host's IPC namespace. |  | Optional: \{\} <br /> |
| `shareProcessNamespace` _boolean_ | shareProcessNamespace shares one process namespace between containers. |  | Optional: \{\} <br /> |
| `schedulerName` _string_ | schedulerName selects the scheduler for the Pods. |  | Optional: \{\} <br /> |
| `runtimeClassName` _string_ | runtimeClassName selects the Pods' RuntimeClass. |  | Optional: \{\} <br /> |
| `dnsPolicy` _[DNSPolicy](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#dnspolicy-v1-core)_ | dnsPolicy sets the Pods' DNS policy. |  | Optional: \{\} <br /> |
| `dnsConfig` _[PodDNSConfig](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#poddnsconfig-v1-core)_ | dnsConfig sets the Pods' DNS parameters. |  | Optional: \{\} <br /> |
| `hostAliases` _[HostAlias](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#hostalias-v1-core) array_ | hostAliases add entries to the Pods' hosts files. |  | Optional: \{\} <br /> |
| `topologySpreadConstraints` _[TopologySpreadConstraint](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#topologyspreadconstraint-v1-core) array_ | topologySpreadConstraints spread the Pods across topology domains. |  | Optional: \{\} <br /> |


#### PodTemplateOverride



PodTemplateOverride customizes the generated engine Pods. It is merged onto
the operator's Pod template with strategic merge, and the values given here
win. Overriding the opa container's image, command, args, ports or probe
handlers, or the operator's volumes, mounts, labels and annotations,
is unsupported. Probe timing can be customized.



_Appears in:_
- [AuthorizationServiceRuntime](#authorizationserviceruntime)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `metadata` _[ResourceMetadata](#resourcemetadata)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  | Optional: \{\} <br /> |
| `spec` _[PodSpecOverride](#podspecoverride)_ | spec customizes the Pod spec. |  | Optional: \{\} <br /> |


#### Policy



Policy defines permissions without subjects or endpoint selection.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.zctx.io/v1alpha1` | | |
| `kind` _string_ | `Policy` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  | Optional: \{\} <br /> |
| `spec` _[PolicySpec](#policyspec)_ | spec defines the policy permissions. |  | Required: \{\} <br /> |


#### PolicyBinding



PolicyBinding attaches principals to a Policy, PolicySet, or native role definition.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.zctx.io/v1alpha1` | | |
| `kind` _string_ | `PolicyBinding` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  | Optional: \{\} <br /> |
| `spec` _[PolicyBindingSpec](#policybindingspec)_ | spec defines the principal binding. |  | Required: \{\} <br /> |


#### PolicyBindingSpec



PolicyBindingSpec attaches principals to one policy target, or to each
PolicySet a selector matches.



_Appears in:_
- [PolicyBinding](#policybinding)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `policyRef` _[PolicyRef](#policyref)_ | policyRef identifies the permission definition. |  | Optional: \{\} <br /> |
| `policySelector` _[PolicySelector](#policyselector)_ | policySelector selects PolicySets by their labels and their namespaces'<br />labels. Each match is delegated to as a policyRef to it would be. |  | Optional: \{\} <br /> |
| `subjects` _[Subject](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#subject-v1-rbac-authorization-k8s-io) array_ | subjects contains exact principals combined by OR. |  | MaxItems: 256 <br />MinItems: 1 <br />Optional: \{\} <br /> |
| `subjectMatch` _[SubjectMatch](#subjectmatch)_ | subjectMatch selects principals with extended fixed-form predicates. |  | Optional: \{\} <br /> |
| `constraints` _[BindingConstraints](#bindingconstraints)_ | constraints narrows the target and its descendants. |  | Optional: \{\} <br /> |


#### PolicyCondition



PolicyCondition is a Rego module deciding whether a policy applies to a request.



_Appears in:_
- [PolicySpec](#policyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `rego` _string_ | rego is a Rego v1 module declaring package condition, whose rule allow<br />decides the condition. |  | MaxLength: 65536 <br />MinLength: 1 <br />Required: \{\} <br /> |


#### PolicyImport



PolicyImport identifies a native Role or ClusterRole and an optional namespace filter.



_Appears in:_
- [PolicySpec](#policyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiGroup` _string_ | apiGroup is the referenced native kind's API group. |  | MaxLength: 253 <br />Optional: \{\} <br /> |
| `kind` _string_ | kind is Role or ClusterRole. |  | Enum: [Role ClusterRole] <br />Required: \{\} <br /> |
| `name` _string_ | name is the referenced native role name. |  | MaxLength: 253 <br />MinLength: 1 <br />Required: \{\} <br /> |
| `namespace` _string_ | namespace is the logical namespace of a Role. Omission means the importing<br />document's namespace. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br />Optional: \{\} <br /> |
| `sourceRef` _[SourceRef](#sourceref)_ | sourceRef selects another allowed PolicySource. |  | Optional: \{\} <br /> |
| `namespaces` _string array_ | namespaces restricts imported resource operations to matching namespaces,<br />as an operation rule's namespaces do. |  | MaxItems: 256 <br />MinItems: 1 <br />items:MaxLength: 63 <br />items:Pattern: `^(\*\|[a-z0-9]([-a-z0-9]*[a-z0-9])?)?$` <br />Optional: \{\} <br /> |


#### PolicyRef



PolicyRef identifies a Policy, PolicySet, Role, or ClusterRole.



_Appears in:_
- [BindingConstraints](#bindingconstraints)
- [PolicyBindingSpec](#policybindingspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiGroup` _string_ | apiGroup is the referenced kind's API group. It is derived from kind when<br />omitted. |  | MaxLength: 253 <br />Optional: \{\} <br /> |
| `kind` _string_ | kind is Policy, PolicySet, Role, or ClusterRole. Omission means Policy. |  | Enum: [Policy PolicySet Role ClusterRole] <br />Optional: \{\} <br /> |
| `name` _string_ | name is the referenced permission definition's name. |  | MaxLength: 253 <br />MinLength: 1 <br />Required: \{\} <br /> |
| `namespace` _string_ | namespace is the logical namespace of a namespaced definition. Omission<br />means the referencing document's namespace. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br />Optional: \{\} <br /> |
| `sourceRef` _[SourceRef](#sourceref)_ | sourceRef selects another allowed PolicySource. |  | Optional: \{\} <br /> |


#### PolicySelector



PolicySelector selects the PolicySets of one source.



_Appears in:_
- [PolicyBindingSpec](#policybindingspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `sourceRef` _[SourceRef](#sourceref)_ | sourceRef selects another allowed PolicySource. Omission means the binding's<br />own source. |  | Optional: \{\} <br /> |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#labelselector-v1-meta)_ | namespaceSelector selects the namespaces whose PolicySets may match,<br />by the namespaces' labels in the source. An empty selector selects every<br />namespace; any other requires the source to collect namespace labels. |  | Required: \{\} <br /> |
| `selector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#labelselector-v1-meta)_ | selector selects PolicySets by their own labels. |  | Required: \{\} <br /> |


#### PolicySet



PolicySet assembles binding references for contextual evaluation.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.zctx.io/v1alpha1` | | |
| `kind` _string_ | `PolicySet` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  | Optional: \{\} <br /> |
| `spec` _[PolicySetSpec](#policysetspec)_ | spec defines the policy graph entry. |  | Required: \{\} <br /> |


#### PolicySetSpec



PolicySetSpec assembles bindings and root prohibitions.



_Appears in:_
- [PolicySet](#policyset)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `bindingRefs` _[BindingRef](#bindingref) array_ | bindingRefs contains custom or native bindings that contribute Allow. |  | MaxItems: 256 <br />Optional: \{\} <br /> |
| `prohibitionRefs` _[BindingRef](#bindingref) array_ | prohibitionRefs contains custom or native bindings that contribute root-only Deny. |  | MaxItems: 256 <br />Optional: \{\} <br /> |


#### PolicySource



PolicySource registers an acquired policy-document source.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.zctx.io/v1alpha1` | | |
| `kind` _string_ | `PolicySource` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  | Optional: \{\} <br /> |
| `spec` _[PolicySourceSpec](#policysourcespec)_ | spec defines source acquisition. |  | Required: \{\} <br /> |
| `status` _[PolicySourceStatus](#policysourcestatus)_ | status reports observed acquisition state. |  | Optional: \{\} <br /> |


#### PolicySourceProvider



PolicySourceProvider selects the provider and configures it.



_Appears in:_
- [PolicySourceSpec](#policysourcespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `type` _[ProviderType](#providertype)_ | type identifies the selected provider. |  | Enum: [Kubernetes] <br />Required: \{\} <br /> |
| `kubernetes` _[KubernetesProvider](#kubernetesprovider)_ | kubernetes configures acquisition from a Kubernetes API. |  | Optional: \{\} <br /> |


#### PolicySourceRego



PolicySourceRego allows the source's documents to carry Rego conditions.



_Appears in:_
- [PolicySourceSpec](#policysourcespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowedBuiltins` _string array_ | allowedBuiltins are the builtins conditions may call. Omission means<br />the release's default builtins. |  | MaxItems: 256 <br />items:MaxLength: 128 <br />items:MinLength: 1 <br />Optional: \{\} <br /> |


#### PolicySourceSpec



PolicySourceSpec defines acquisition, collection and lifecycle.



_Appears in:_
- [PolicySource](#policysource)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `provider` _[PolicySourceProvider](#policysourceprovider)_ | provider selects and configures the acquisition provider. |  | Required: \{\} <br /> |
| `collection` _[KeyRange](#keyrange) array_ | collection contains the explicit ranges collected by this source. |  | MaxItems: 64 <br />Required: \{\} <br /> |
| `namespaceLabels` _[NamespaceLabels](#namespacelabels)_ | namespaceLabels selects whether the source reads the labels<br />of the namespaces its collection covers: every namespace when a range<br />selects "*", otherwise each namespace a range names. A policySelector's<br />non-empty namespaceSelector requires Collect. | Ignore | Enum: [Collect Ignore] <br />Optional: \{\} <br /> |
| `synchronization` _[Synchronization](#synchronization)_ | synchronization selects whether the source reads from its provider.<br />Paused stops reading and keeps serving the last complete view. | Active | Enum: [Active Paused] <br />Optional: \{\} <br /> |
| `contribution` _[Contribution](#contribution)_ | contribution selects whether the source's documents take part in compiled<br />policy. Toggling it never restarts acquisition. | Active | Enum: [Active Inert] <br />Optional: \{\} <br /> |
| `rego` _[PolicySourceRego](#policysourcerego)_ | rego allows the source's documents to carry Rego conditions. Omission<br />forbids them, here and in every use beneath this source. |  | Optional: \{\} <br /> |


#### PolicySourceStatus



PolicySourceStatus reports acquisition health.



_Appears in:_
- [PolicySource](#policysource)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | observedGeneration is the spec generation assessed by this status. |  | Optional: \{\} <br /> |
| `lastAdmittedTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#time-v1-meta)_ | lastAdmittedTime records when the source last admitted a complete view<br />whose documents changed, or which ended a period of failed acquisition. |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#condition-v1-meta) array_ | conditions holds Synchronized, which reports whether the latest acquisition<br />is complete. |  | Optional: \{\} <br /> |
| `issues` _[Issue](#issue) array_ | issues contains bounded attributed diagnostics for the documents<br />in the source's view. |  | MaxItems: 128 <br />Optional: \{\} <br /> |
| `issuesTruncated` _boolean_ | issuesTruncated reports that additional diagnostics were omitted. |  | Optional: \{\} <br /> |


#### PolicySpec



PolicySpec defines a reusable permission set.



_Appears in:_
- [Policy](#policy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `include` _[OperationRule](#operationrule) array_ | include contains locally allowed operations. Omitted together with imports<br />on a Policy with a condition, it allows every operation the condition<br />allows. |  | MaxItems: 256 <br />Optional: \{\} <br /> |
| `exclude` _[OperationRule](#operationrule) array_ | exclude contains operations removed from the local and imported union. |  | MaxItems: 256 <br />Optional: \{\} <br /> |
| `imports` _[PolicyImport](#policyimport) array_ | imports contains native Role and ClusterRole permission definitions. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `condition` _[PolicyCondition](#policycondition)_ | condition narrows the policy to the requests its Rego allows. |  | Optional: \{\} <br /> |


#### ProgramType

_Underlying type:_ _string_

ProgramType identifies a request integration.

_Validation:_
- Enum: [Kubernetes]

_Appears in:_
- [AuthorizationProgram](#authorizationprogram)

| Field | Description |
| --- | --- |
| `Kubernetes` |  |


#### ProviderType

_Underlying type:_ _string_

ProviderType identifies a PolicySource acquisition provider.

_Validation:_
- Enum: [Kubernetes]

_Appears in:_
- [PolicySourceProvider](#policysourceprovider)

| Field | Description |
| --- | --- |
| `Kubernetes` |  |


#### QualifiedDocumentRef



QualifiedDocumentRef identifies a document in status diagnostics.



_Appears in:_
- [Issue](#issue)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `group` _string_ | group is the canonical API group. |  |  |
| `kind` _string_ | kind is the canonical kind. |  |  |
| `namespace` _string_ | namespace is present for namespaced document kinds. |  |  |
| `name` _string_ | name is the document name. |  |  |


#### ResourceMetadata



ResourceMetadata customizes labels and annotations on a generated resource.



_Appears in:_
- [AuthorizationServiceRuntime](#authorizationserviceruntime)
- [PodTemplateOverride](#podtemplateoverride)
- [ServiceTemplateOverride](#servicetemplateoverride)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `labels` _object (keys:string, values:string)_ | labels are merged with the operator's labels. A label the operator also<br />sets takes the value given here. |  | Optional: \{\} <br /> |
| `annotations` _object (keys:string, values:string)_ | annotations are merged with the operator's annotations. |  | Optional: \{\} <br /> |


#### RuntimeType

_Underlying type:_ _string_

RuntimeType selects the engine workload kind. Deployment runs a fixed
number of engines, and DaemonSet runs one on each node the Pod template can
schedule on.

_Validation:_
- Enum: [Deployment DaemonSet]

_Appears in:_
- [AuthorizationServiceRuntime](#authorizationserviceruntime)

| Field | Description |
| --- | --- |
| `Deployment` | RuntimeTypeDeployment runs the engines as a Deployment.<br /> |
| `DaemonSet` | RuntimeTypeDaemonSet runs the engines as a DaemonSet.<br /> |


#### SecretKeyRef



SecretKeyRef identifies a key in a Secret in the containing control
resource's namespace.



_Appears in:_
- [CABundleRef](#cabundleref)
- [KubeconfigReference](#kubeconfigreference)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | name is the Secret name. |  | MaxLength: 253 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$` <br />Required: \{\} <br /> |
| `key` _string_ | key is the Secret data key. |  | MaxLength: 253 <br />MinLength: 1 <br />Pattern: `^[-._a-zA-Z0-9]+$` <br />Required: \{\} <br /> |


#### SecretReference



SecretReference identifies a Secret in the AuthorizationService's namespace.



_Appears in:_
- [ServerTLS](#servertls)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | name is the Secret name. |  | MaxLength: 253 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$` <br />Required: \{\} <br /> |


#### ServerTLS



ServerTLS configures the certificate the engines serve. It must be valid
for the listener Service's DNS name, authz-<name>.<namespace>.svc, which
is the TLS server name the operator and rendered caller configurations
verify.



_Appears in:_
- [AuthorizationServiceTLS](#authorizationservicetls)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `secretRef` _[SecretReference](#secretreference)_ | secretRef identifies a kubernetes.io/tls Secret holding tls.crt and tls.key.<br />The engines reload it in place, so renewing the certificate never restarts<br />them. |  | Required: \{\} <br /> |
| `caRef` _[CABundleRef](#cabundleref)_ | caRef identifies the CA bundle the operator verifies the serving certificate<br />with. |  | Required: \{\} <br /> |


#### ServicePortOverride



ServicePortOverride customizes one of the listener Service's ports.



_Appears in:_
- [ServiceSpecOverride](#servicespecoverride)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | name identifies the port to customize. |  | MaxLength: 15 <br />MinLength: 1 <br />Required: \{\} <br /> |
| `protocol` _[Protocol](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#protocol-v1-core)_ | protocol is the port's IP protocol. |  | Optional: \{\} <br /> |
| `appProtocol` _string_ | appProtocol is the port's application protocol. |  | Optional: \{\} <br /> |
| `port` _integer_ | port is the port the Service exposes. |  | Maximum: 65535 <br />Minimum: 1 <br />Optional: \{\} <br /> |
| `nodePort` _integer_ | nodePort requests a specific node port for NodePort and LoadBalancer<br />Services. Zero releases an allocated node port. |  | Maximum: 65535 <br />Minimum: 0 <br />Optional: \{\} <br /> |


#### ServiceSpecOverride



ServiceSpecOverride contains the Service spec fields an AuthorizationService
can customize. The operator owns the selector and the engine's target port.



_Appears in:_
- [ServiceTemplateOverride](#servicetemplateoverride)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `ports` _[ServicePortOverride](#serviceportoverride) array_ | ports merge with the operator's ports by name. The engine port is named<br />https. |  | MaxItems: 16 <br />Optional: \{\} <br /> |
| `clusterIP` _string_ | clusterIP requests a specific cluster IP. It is immutable once allocated. |  | Optional: \{\} <br /> |
| `clusterIPs` _string array_ | clusterIPs requests specific cluster IPs. They are immutable once allocated. |  | Optional: \{\} <br /> |
| `type` _[ServiceType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#servicetype-v1-core)_ | type is ClusterIP, NodePort or LoadBalancer. |  | Optional: \{\} <br /> |
| `externalIPs` _string array_ | externalIPs are additional IPs that route to the Service. |  | Optional: \{\} <br /> |
| `sessionAffinity` _[ServiceAffinity](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#serviceaffinity-v1-core)_ | sessionAffinity sets the Service's session affinity. |  | Optional: \{\} <br /> |
| `loadBalancerIP` _string_ | loadBalancerIP requests a load balancer IP where the provider supports it. |  | Optional: \{\} <br /> |
| `loadBalancerSourceRanges` _string array_ | loadBalancerSourceRanges restrict the clients a load balancer admits. |  | Optional: \{\} <br /> |
| `externalTrafficPolicy` _[ServiceExternalTrafficPolicy](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#serviceexternaltrafficpolicy-v1-core)_ | externalTrafficPolicy routes external traffic cluster-wide or node-locally. |  | Optional: \{\} <br /> |
| `healthCheckNodePort` _integer_ | healthCheckNodePort sets the load balancer health-check node port. |  | Optional: \{\} <br /> |
| `publishNotReadyAddresses` _boolean_ | publishNotReadyAddresses publishes engines before they are ready. |  | Optional: \{\} <br /> |
| `sessionAffinityConfig` _[SessionAffinityConfig](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#sessionaffinityconfig-v1-core)_ | sessionAffinityConfig configures session affinity. |  | Optional: \{\} <br /> |
| `ipFamilies` _[IPFamily](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#ipfamily-v1-core) array_ | ipFamilies selects the Service's IP families. |  | Optional: \{\} <br /> |
| `ipFamilyPolicy` _[IPFamilyPolicy](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#ipfamilypolicy-v1-core)_ | ipFamilyPolicy selects single- or dual-stack addressing. |  | Optional: \{\} <br /> |
| `allocateLoadBalancerNodePorts` _boolean_ | allocateLoadBalancerNodePorts controls node port allocation for load balancers. |  | Optional: \{\} <br /> |
| `loadBalancerClass` _string_ | loadBalancerClass selects the load balancer implementation. |  | Optional: \{\} <br /> |
| `internalTrafficPolicy` _[ServiceInternalTrafficPolicy](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.37/#serviceinternaltrafficpolicy-v1-core)_ | internalTrafficPolicy routes internal traffic cluster-wide or node-locally. |  | Optional: \{\} <br /> |
| `trafficDistribution` _string_ | trafficDistribution expresses a preference for how traffic reaches engines. |  | Optional: \{\} <br /> |


#### ServiceTemplateOverride



ServiceTemplateOverride customizes the generated listener Service.
It is merged onto the operator's Service with strategic merge, and the values
given here win.



_Appears in:_
- [AuthorizationServiceSpec](#authorizationservicespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `metadata` _[ResourceMetadata](#resourcemetadata)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  | Optional: \{\} <br /> |
| `spec` _[ServiceSpecOverride](#servicespecoverride)_ | spec customizes the Service spec. |  | Optional: \{\} <br /> |


#### SourceRef



SourceRef identifies a PolicySource in the trusted control API.



_Appears in:_
- [BindingConstraints](#bindingconstraints)
- [BindingRef](#bindingref)
- [Endpoint](#endpoint)
- [Issue](#issue)
- [PolicyImport](#policyimport)
- [PolicyRef](#policyref)
- [PolicySelector](#policyselector)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `namespace` _string_ | namespace is the PolicySource namespace. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br />Required: \{\} <br /> |
| `name` _string_ | name is the PolicySource name. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$` <br />Required: \{\} <br /> |




#### SubjectMatch



SubjectMatch selects the principals that satisfy every requirement. Like
an empty label selector, an empty subjectMatch selects every principal.



_Appears in:_
- [PolicyBindingSpec](#policybindingspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `requirements` _[SubjectRequirement](#subjectrequirement) array_ | requirements are ANDed principal predicates. |  | MaxItems: 64 <br />Optional: \{\} <br /> |


#### SubjectRequirement



SubjectRequirement tests one principal attribute. Requirements are ANDed.



_Appears in:_
- [SubjectMatch](#subjectmatch)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `kind` _string_ | kind selects the principal attribute. |  | Enum: [User Group ServiceAccount UID Extra] <br />Required: \{\} <br /> |
| `operator` _string_ | operator compares the selected values or tests presence. |  | Enum: [In NotIn Exists DoesNotExist StartsWith NotStartsWith] <br />Required: \{\} <br /> |
| `names` _string array_ | names supplies operands for User, Group, or ServiceAccount. |  | MaxItems: 256 <br />MinItems: 1 <br />items:MinLength: 1 <br />Optional: \{\} <br /> |
| `namespace` _string_ | namespace is required only for ServiceAccount. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br />Optional: \{\} <br /> |
| `key` _string_ | key is required only for Extra. |  | MaxLength: 253 <br />MinLength: 1 <br />Optional: \{\} <br /> |
| `values` _string array_ | values supplies operands for UID or Extra. |  | MaxItems: 256 <br />MinItems: 1 <br />Optional: \{\} <br /> |


#### Synchronization

_Underlying type:_ _string_

Synchronization selects whether a PolicySource reads from its provider.
Active reads continuously. Paused stops reading and keeps serving
the source's last complete view.

_Validation:_
- Enum: [Active Paused]

_Appears in:_
- [PolicySourceSpec](#policysourcespec)

| Field | Description |
| --- | --- |
| `Active` | SynchronizationActive reads from the provider continuously.<br /> |
| `Paused` | SynchronizationPaused stops reading and keeps the last complete view.<br /> |


