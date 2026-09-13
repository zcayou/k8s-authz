package kubernetes

import (
	"errors"
	"fmt"
	"strings"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ParseKubeconfig loads a kubeconfig's current context. It rejects credentials
// that depend on anything outside the kubeconfig, such as exec or auth-provider
// plugins and file references, and connections that don't verify an HTTPS
// server.
func ParseKubeconfig(data []byte) (*rest.Config, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig(data)
	if err != nil {
		return nil, fmt.Errorf("parse kubeconfig: %w", err)
	}
	switch {
	case config.ExecProvider != nil || config.AuthProvider != nil:
		return nil, errors.New("kubeconfig uses an external authentication plugin")
	case config.CAFile != "" || config.CertFile != "" || config.KeyFile != "" || config.BearerTokenFile != "":
		return nil, errors.New("kubeconfig refers to external files")
	case config.Insecure:
		return nil, errors.New("kubeconfig disables TLS verification")
	case !strings.HasPrefix(config.Host, "https://"):
		return nil, errors.New("kubeconfig server must be an https URL")
	}
	return config, nil
}

// Origin returns the normalized URL of the API server config reaches.
// It identifies the documents a source serves and never includes credentials.
func Origin(config *rest.Config) (string, error) {
	server, _, err := rest.DefaultServerUrlFor(config)
	if err != nil {
		return "", fmt.Errorf("parse API server URL: %w", err)
	}
	server.Host = strings.ToLower(server.Host)
	server.Path = strings.TrimSuffix(server.Path, "/")
	server.RawPath, server.RawQuery, server.Fragment, server.User = "", "", "", nil
	return server.String(), nil
}
