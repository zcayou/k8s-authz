package model

import (
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
)

const (
	KindPolicy             = "Policy"
	KindPolicyBinding      = "PolicyBinding"
	KindPolicySet          = "PolicySet"
	KindRole               = "Role"
	KindClusterRole        = "ClusterRole"
	KindRoleBinding        = "RoleBinding"
	KindClusterRoleBinding = "ClusterRoleBinding"
)

// DocumentKind is the API resource that serves a document kind.
type DocumentKind struct {
	Resource   schema.GroupVersionResource
	Namespaced bool
}

// DocumentKinds are the kinds a source collects, by kind name.
var DocumentKinds = map[string]DocumentKind{
	KindPolicy:             {Resource: api.GroupVersion.WithResource("policies"), Namespaced: true},
	KindPolicyBinding:      {Resource: api.GroupVersion.WithResource("policybindings"), Namespaced: true},
	KindPolicySet:          {Resource: api.GroupVersion.WithResource("policysets"), Namespaced: true},
	KindRole:               {Resource: rbacv1.SchemeGroupVersion.WithResource("roles"), Namespaced: true},
	KindClusterRole:        {Resource: rbacv1.SchemeGroupVersion.WithResource("clusterroles")},
	KindRoleBinding:        {Resource: rbacv1.SchemeGroupVersion.WithResource("rolebindings"), Namespaced: true},
	KindClusterRoleBinding: {Resource: rbacv1.SchemeGroupVersion.WithResource("clusterrolebindings")},
}
