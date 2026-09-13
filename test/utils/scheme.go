package utils

import (
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
)

// Scheme registers the built-in Kubernetes and product types, as the manager
// does.
func Scheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()
	for _, register := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, api.AddToScheme} {
		if err := register(scheme); err != nil {
			return nil, err
		}
	}
	return scheme, nil
}
