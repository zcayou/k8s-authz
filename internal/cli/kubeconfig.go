package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
)

// connection is a command's connection to kube-apiserver, which kubectl's
// --kubeconfig and override flags configure.
type connection struct {
	loading   *clientcmd.ClientConfigLoadingRules
	overrides clientcmd.ConfigOverrides
	flags     *pflag.FlagSet
}

// cluster is a connection to kube-apiserver: its configuration, the namespace
// it selects, and a client for the kinds the commands read.
type cluster struct {
	config    *rest.Config
	namespace string
	client    client.Client
}

// bindConnectionFlags adds kubectl's --kubeconfig and override flags
// to command.
func bindConnectionFlags(command *cobra.Command) *connection {
	result := &connection{loading: clientcmd.NewDefaultClientConfigLoadingRules(), flags: pflag.NewFlagSet("connection", pflag.ContinueOnError)}
	result.flags.StringVar(&result.loading.ExplicitPath, clientcmd.RecommendedConfigPathFlag, "", "path to the kubeconfig file")
	clientcmd.BindOverrideFlags(&result.overrides, result.flags, clientcmd.RecommendedConfigOverrideFlags(""))
	command.Flags().AddFlagSet(result.flags)
	return result
}

// connect loads the kubeconfig and builds a client from it. The client maps
// its two kinds statically, so it reads without discovery.
func (c *connection) connect() (*cluster, error) {
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(c.loading, &c.overrides)
	namespace, _, err := clientConfig.Namespace()
	if err != nil {
		return nil, fmt.Errorf("resolve namespace: %w", err)
	}
	config, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	scheme := runtime.NewScheme()
	if err = errors.Join(corev1.AddToScheme(scheme), api.AddToScheme(scheme)); err != nil {
		return nil, err
	}
	mapper := apimeta.NewDefaultRESTMapper(nil)
	mapper.Add(corev1.SchemeGroupVersion.WithKind("Pod"), apimeta.RESTScopeNamespace)
	mapper.Add(api.GroupVersion.WithKind("AuthorizationService"), apimeta.RESTScopeNamespace)
	reader, err := client.New(config, client.Options{Scheme: scheme, Mapper: mapper})
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return &cluster{config: config, namespace: namespace, client: reader}, nil
}
