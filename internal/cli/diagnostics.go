package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"k8s.io/klog/v2"
	streamhttp "k8s.io/streaming/pkg/httpstream"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/zcayou/k8s-authz/internal/diagnostics"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/resources"
)

const (
	// defaultOperatorNamespace is the namespace config/default installs
	// the operator into.
	defaultOperatorNamespace = "k8s-authz-system"
	// diagnosticsPortName names the operator container's diagnostics port.
	diagnosticsPortName = "diagnostics"
	diagnosticsTimeout  = 30 * time.Second
)

// operatorLabels select the operator's pods. Both installations set this
// label to a fixed value, whatever the release is named.
var operatorLabels = map[string]string{"authorization.zctx.io/component": "operator"}

// snapshotRequest names the engine pod whose installed snapshot explain reads.
// An empty pod selects any ready engine pod of the service.
type snapshotRequest struct {
	namespace         string
	service           string
	pod               string
	operatorNamespace string
}

// readInstalledSnapshot reads the export of the snapshot installed
// on the requested engine pod from the operator's diagnostics endpoint.
// It reaches a ready operator pod through a port-forward that kube-apiserver
// opens with the caller's credentials, and presents the same credentials over
// the tunnel.
func readInstalledSnapshot(ctx context.Context, cluster *cluster, request snapshotRequest) ([]byte, error) {
	if request.pod == "" {
		pod, err := firstReadyPod(ctx, cluster.client, request.namespace, resources.ServiceEngineSelector(request.service))
		if err != nil {
			return nil, fmt.Errorf("select an engine pod of AuthorizationService %s/%s: %w", request.namespace, request.service, err)
		}
		request.pod = pod.Name
	}
	operator, port, err := diagnosticsPod(ctx, cluster.client, request.operatorNamespace)
	if err != nil {
		return nil, err
	}
	forwarded, stop, err := forward(ctx, cluster.config, operator, port)
	if err != nil {
		return nil, err
	}
	defer stop()
	return getSnapshot(ctx, cluster.config, forwarded, diagnostics.SnapshotPath(request.namespace, request.service, request.pod))
}

// diagnosticsPod returns a ready operator pod in namespace and its diagnostics
// port. Every operator replica serves diagnostics.
func diagnosticsPod(ctx context.Context, reader client.Reader, namespace string) (*corev1.Pod, int32, error) {
	pod, err := firstReadyPod(ctx, reader, namespace, operatorLabels)
	if err != nil {
		return nil, 0, fmt.Errorf("select an operator pod in namespace %s: %w", namespace, err)
	}
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			if port.Name == diagnosticsPortName {
				return pod, port.ContainerPort, nil
			}
		}
	}
	return nil, 0, fmt.Errorf("operator Pod %s/%s has no %s port", pod.Namespace, pod.Name, diagnosticsPortName)
}

// firstReadyPod returns the first ready pod, by name, of the pods in namespace
// that carry labels.
func firstReadyPod(ctx context.Context, reader client.Reader, namespace string, labels map[string]string) (*corev1.Pod, error) {
	var list corev1.PodList
	if err := reader.List(ctx, &list, client.InNamespace(namespace), client.MatchingLabels(labels)); err != nil {
		return nil, err
	}
	slices.SortFunc(list.Items, func(a, b corev1.Pod) int { return strings.Compare(a.Name, b.Name) })
	for index := range list.Items {
		if resources.PodReady(&list.Items[index]) {
			return &list.Items[index], nil
		}
	}
	return nil, errors.New("no ready Pod")
}

// forward opens a port-forward to port on pod and returns the local address
// it listens on, and a function that closes it. Like kubectl, it tunnels
// through a websocket and falls back to SPDY when kube-apiserver refuses
// the websocket upgrade.
func forward(ctx context.Context, config *rest.Config, pod *corev1.Pod, port int32) (string, func(), error) {
	dialer, err := portForwardDialer(ctx, config, pod)
	if err != nil {
		return "", nil, fmt.Errorf("create port-forward to operator Pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	running, cancel := context.WithCancel(ctx)
	ready := make(chan struct{})
	forwarder, err := portforward.NewOnAddressesForStreamingWithContext(running, dialer, []string{"127.0.0.1"}, []string{"0:" + strconv.Itoa(int(port))}, ready, io.Discard, io.Discard)
	if err != nil {
		cancel()
		return "", nil, fmt.Errorf("create port-forward: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- forwarder.ForwardPorts() }()
	stop := func() {
		cancel()
		<-done
	}
	select {
	case <-ready:
	case err = <-done:
		cancel()
		return "", nil, fmt.Errorf("port-forward to operator Pod %s/%s: %w", pod.Namespace, pod.Name, err)
	case <-ctx.Done():
		stop()
		return "", nil, ctx.Err()
	}
	ports, err := forwarder.GetPorts()
	if err != nil {
		stop()
		return "", nil, fmt.Errorf("port-forward to operator Pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(ports[0].Local))), stop, nil
}

// portForwardDialer dials pod's portforward subresource as kubectl does:
// SPDY over a websocket, falling back to SPDY.
func portForwardDialer(ctx context.Context, config *rest.Config, pod *corev1.Pod) (streamhttp.Dialer, error) {
	host, apiPath, err := rest.DefaultServerURL(config.Host, "/api", corev1.SchemeGroupVersion, rest.IsConfigTransportTLS(*config))
	if err != nil {
		return nil, err
	}
	location := host.JoinPath(apiPath, "namespaces", pod.Namespace, "pods", pod.Name, "portforward")
	transport, upgrader, err := spdy.RoundTripperFor(config)
	if err != nil {
		return nil, err
	}
	tunneling, err := portforward.NewSPDYOverWebsocketDialerForStreamingWithLogger(klog.FromContext(ctx), location, config)
	if err != nil {
		return nil, err
	}
	return portforward.NewFallbackDialerForStreaming(tunneling, spdy.NewDialerForStreaming(upgrader, &http.Client{Transport: transport}, http.MethodPost, location), func(err error) bool {
		return streamhttp.IsUpgradeFailure(err) || streamhttp.IsHTTPSProxyError(err)
	}), nil
}

// getSnapshot requests path from the diagnostics endpoint at address
// with config's credentials, directly rather than through config's proxy.
// The port-forward authenticated the endpoint, so its serving certificate
// isn't verified.
func getSnapshot(ctx context.Context, config *rest.Config, address, path string) ([]byte, error) {
	tunnel := rest.CopyConfig(config)
	tunnel.Host = "https://" + address
	tunnel.CAFile, tunnel.CAData, tunnel.ServerName, tunnel.Insecure = "", nil, "", true
	tunnel.Impersonate, tunnel.Proxy = rest.ImpersonationConfig{}, nil
	tunnel.Timeout = diagnosticsTimeout
	httpClient, err := rest.HTTPClientFor(tunnel)
	if err != nil {
		return nil, fmt.Errorf("create diagnostics client: %w", err)
	}
	defer httpClient.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, tunnel.Host+path, nil)
	if err != nil {
		return nil, err
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("read installed snapshot: %w", err)
	}
	data, err := readLimited(response.Body, "installed snapshot", engine.MaxExportBytes)
	if err = errors.Join(err, response.Body.Close()); err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("diagnostics returned HTTP %d: %s", response.StatusCode, bytes.TrimSpace(data[:min(len(data), 1024)]))
	}
	return data, nil
}
