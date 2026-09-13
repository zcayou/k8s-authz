package utils

import (
	"context"
	"errors"
	"fmt"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// ServiceAccountKubeconfig requests a two-hour token for account through
// config and returns a kubeconfig that presents it to config's API server,
// trusting config's CA. server is the address the kubeconfig's user reaches
// that API server at, which can differ from config.Host.
func ServiceAccountKubeconfig(ctx context.Context, config *rest.Config, account types.NamespacedName, server string) ([]byte, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	token, err := clientset.CoreV1().ServiceAccounts(account.Namespace).CreateToken(ctx, account.Name, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: new(int64(7200))},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("request token for %s: %w", account, err)
	}
	loaded := rest.CopyConfig(config)
	if err := rest.LoadTLSFiles(loaded); err != nil {
		return nil, fmt.Errorf("read API server CA: %w", err)
	}
	if len(loaded.CAData) == 0 {
		return nil, errors.New("API server CA is not configured")
	}
	return clientcmd.Write(clientcmdapi.Config{
		Clusters:       map[string]*clientcmdapi.Cluster{account.Name: {Server: server, CertificateAuthorityData: loaded.CAData}},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{account.Name: {Token: token.Status.Token}},
		Contexts:       map[string]*clientcmdapi.Context{account.Name: {Cluster: account.Name, AuthInfo: account.Name}},
		CurrentContext: account.Name,
	})
}
