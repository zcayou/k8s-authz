//go:build e2e

package e2e

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/zcayou/k8s-authz/test/utils"
)

// installBaseline installs the control cluster's policy documents, the sources
// that read them and the member's, and the fleet service every spec starts
// from, then waits for the service to converge.
func (e *environment) installBaseline(ctx context.Context) {
	GinkgoHelper()
	Expect(apply(ctx, namespaces)).To(Succeed())
	readerKubeconfig, err := e.remoteReaderKubeconfig(ctx)
	Expect(err).NotTo(HaveOccurred())
	serving, err := e.servingAuthority.Issue("k8s-authz-e2e-listener", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		listenerName+"."+controlNamespace+".svc")
	Expect(err).NotTo(HaveOccurred())
	for _, secret := range []corev1.Secret{
		tlsSecret("listener-server", serving),
		{ObjectMeta: metav1.ObjectMeta{Name: "serving-ca"}, Data: map[string][]byte{caKey: e.servingAuthority.CertificatePEM}},
		{ObjectMeta: metav1.ObjectMeta{Name: "client-ca"}, Data: map[string][]byte{caKey: e.callerAuthority.CertificatePEM}},
		{ObjectMeta: metav1.ObjectMeta{Name: "remote-kubeconfig"}, Data: map[string][]byte{"kubeconfig": readerKubeconfig}},
	} {
		secret.Namespace = controlNamespace
		Expect(applySecret(ctx, secret)).To(Succeed())
	}
	Expect(apply(ctx, localDocuments+fmt.Sprintf(fleetService, listenerNodePort,
		e.apiServerCaller.Certificate.Subject.CommonName, e.memberCaller.Certificate.Subject.CommonName))).To(Succeed())
	expectConverged(ctx, 5*time.Minute)
}

// remoteReaderKubeconfig returns the kubeconfig with which the control
// cluster's pods read the member's API server as the remote reader
// ServiceAccount. Only the remote policy namespace's documents and their CRDs
// are visible to it.
func (e *environment) remoteReaderKubeconfig(ctx context.Context) ([]byte, error) {
	config, err := clientcmd.BuildConfigFromFlags("", e.member.kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load the member kubeconfig: %w", err)
	}
	account := types.NamespacedName{Namespace: remotePolicyNamespace, Name: remoteReaderName}
	return utils.ServiceAccountKubeconfig(ctx, config, account, e.memberServer)
}

const namespaces = `apiVersion: v1
kind: Namespace
metadata:
  name: authz-system
---
apiVersion: v1
kind: Namespace
metadata:
  name: e2e-local
---
apiVersion: v1
kind: Namespace
metadata:
  name: team-one
---
`

const memberNamespaces = `apiVersion: v1
kind: Namespace
metadata:
  name: e2e-remote
---
apiVersion: v1
kind: Namespace
metadata:
  name: team-one
---
`

const remoteReader = `apiVersion: v1
kind: ServiceAccount
metadata:
  namespace: e2e-remote
  name: remote-reader
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: e2e-remote
  name: remote-reader
rules:
  - apiGroups: [authorization.zctx.io]
    resources: [policies, policybindings, policysets]
    verbs: [list, watch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: e2e-remote
  name: remote-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: remote-reader
subjects:
  - kind: ServiceAccount
    namespace: e2e-remote
    name: remote-reader
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: remote-reader
rules:
  - apiGroups: [apiextensions.k8s.io]
    resources: [customresourcedefinitions]
    resourceNames: [policies.authorization.zctx.io, policybindings.authorization.zctx.io, policysets.authorization.zctx.io]
    verbs: [list, watch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: remote-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: remote-reader
subjects:
  - kind: ServiceAccount
    namespace: e2e-remote
    name: remote-reader
---
`

const remoteDocuments = `apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySet
metadata:
  namespace: e2e-remote
  name: team
spec:
  bindingRefs:
    - name: admins
---
apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: e2e-remote
  name: namespace-admin
spec:
  include:
    - apiGroups: ["*"]
      resources: ["*"]
      verbs: ["*"]
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: e2e-remote
  name: admins
spec:
  subjects:
    - kind: Group
      apiGroup: rbac.authorization.k8s.io
      name: oidc:e2e-admins
  policyRef:
    name: namespace-admin
---
`

const localDocuments = `apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySource
metadata:
  namespace: authz-system
  name: local
spec:
  provider:
    type: Kubernetes
  collection:
    - kinds: [Policy, PolicyBinding, PolicySet]
      namespaces: [e2e-local]
      names: ["*"]
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySource
metadata:
  namespace: authz-system
  name: remote
spec:
  provider:
    type: Kubernetes
    kubernetes:
      kubeconfig:
        secretRef:
          name: remote-kubeconfig
          key: kubeconfig
  collection:
    - kinds: [Policy, PolicyBinding, PolicySet]
      namespaces: [e2e-remote]
      names: ["*"]
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySet
metadata:
  namespace: e2e-local
  name: root
spec:
  bindingRefs:
    - name: remote-team
---
apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: e2e-local
  name: team-bound
spec:
  include:
    - apiGroups: ["*"]
      resources: ["*"]
      verbs: ["*"]
      namespaces: [team-one]
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: e2e-local
  name: remote-team
spec:
  subjectMatch: {}
  constraints:
    policyRef:
      name: team-bound
  policyRef:
    kind: PolicySet
    sourceRef:
      namespace: authz-system
      name: remote
    namespace: e2e-remote
    name: team
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: e2e-local
  name: oidc
spec:
  subjectMatch:
    requirements:
      - kind: Group
        operator: StartsWith
        names: ["oidc:"]
  policyRef:
    kind: PolicySet
    name: root
  constraints:
    sourceRefs:
      - namespace: authz-system
        name: local
      - namespace: authz-system
        name: remote
    maxDepth: 1
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: e2e-local
  name: native
spec:
  subjectMatch:
    requirements:
      - kind: User
        operator: StartsWith
        names: ["oidc:native-"]
  policyRef:
    name: empty
---
apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: e2e-local
  name: empty
spec:
  include: []
---
`

// fleetService is the AuthorizationService, formatted with the listener's
// NodePort and the control and member API servers' caller Common Names.
const fleetService = `apiVersion: authorization.zctx.io/v1alpha1
kind: AuthorizationService
metadata:
  namespace: authz-system
  name: fleet
spec:
  runtime:
    type: Deployment
    deployment:
      replicas: 2
    minReadyReplicas: 1
  listener:
    spec:
      type: NodePort
      clusterIP: 10.96.0.11
      ports:
        - name: https
          nodePort: %d
  tls:
    server:
      secretRef:
        name: listener-server
      caRef:
        secretKeyRef:
          name: serving-ca
          key: ca.crt
    client:
      caRef:
        secretKeyRef:
          name: client-ca
          key: ca.crt
  program:
    type: Kubernetes
  endpoints:
    - name: cluster
      callers:
        - commonName: %q
      sourceRefs:
        - namespace: authz-system
          name: local
        - namespace: authz-system
          name: remote
      whenEvaluationFails: Deny
      authorities:
        - bindingRef:
            sourceRef:
              namespace: authz-system
              name: local
            namespace: e2e-local
            name: oidc
          whenNoPolicyAllows: Deny
    - name: member
      callers:
        - commonName: %q
      sourceRefs:
        - namespace: authz-system
          name: local
        - namespace: authz-system
          name: remote
      whenEvaluationFails: Deny
      authorities:
        - bindingRef:
            sourceRef:
              namespace: authz-system
              name: local
            namespace: e2e-local
            name: oidc
          whenNoPolicyAllows: Deny
`
