package cli_test

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	streamhttp "k8s.io/streaming/pkg/httpstream"
	"k8s.io/streaming/pkg/httpstream/spdy"
)

// fakeAPIServer serves the AuthorizationService, Pod and port-forward requests
// the commands make. It refuses the websocket port-forward upgrade and speaks
// the SPDY protocol the dialer falls back to. Every port-forward reaches
// forwarded, whichever pod and port it names.
type fakeAPIServer struct {
	server    *httptest.Server
	objects   []runtime.Object
	forwarded string
	// proxy is the proxy-url of the kubeconfigs it writes, if set.
	proxy string

	mutex    sync.Mutex
	forwards []string
	tokens   []string
}

func newFakeAPIServer(forwarded string, objects ...runtime.Object) *fakeAPIServer {
	GinkgoHelper()
	fake := &fakeAPIServer{objects: objects, forwarded: forwarded}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /apis/authorization.zctx.io/v1alpha1/namespaces/{namespace}/authorizationservices/{name}", fake.get)
	mux.HandleFunc("GET /api/v1/namespaces/{namespace}/pods", fake.listPods)
	mux.HandleFunc("/api/v1/namespaces/{namespace}/pods/{name}/portforward", fake.portForward)
	fake.server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fake.mutex.Lock()
		fake.tokens = append(fake.tokens, request.Header.Get("Authorization"))
		fake.mutex.Unlock()
		mux.ServeHTTP(writer, request)
	}))
	DeferCleanup(fake.server.Close)
	return fake
}

// kubeconfig writes a kubeconfig that reaches the server with token and returns
// its path.
func (f *fakeAPIServer) kubeconfig(directory, token string) string {
	GinkgoHelper()
	authority := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw})
	data, err := clientcmd.Write(clientcmdapi.Config{
		CurrentContext: "caller",
		Clusters:       map[string]*clientcmdapi.Cluster{"api": {Server: f.server.URL, CertificateAuthorityData: authority, ProxyURL: f.proxy}},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{"caller": {Token: token}},
		Contexts:       map[string]*clientcmdapi.Context{"caller": {Cluster: "api", AuthInfo: "caller"}},
	})
	Expect(err).NotTo(HaveOccurred())
	path := filepath.Join(directory, "kubeconfig")
	Expect(os.WriteFile(path, data, 0o600)).To(Succeed())
	return path
}

func (f *fakeAPIServer) get(writer http.ResponseWriter, request *http.Request) {
	defer GinkgoRecover()
	for _, object := range f.objects {
		accessor, ok := object.(metav1.Object)
		if _, pod := object.(*corev1.Pod); ok && !pod && accessor.GetNamespace() == request.PathValue("namespace") && accessor.GetName() == request.PathValue("name") {
			writeJSON(writer, object)
			return
		}
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusNotFound)
	status := apierrors.NewNotFound(schema.GroupResource{Group: "authorization.zctx.io", Resource: "authorizationservices"}, request.PathValue("name")).ErrStatus
	status.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}
	Expect(json.NewEncoder(writer).Encode(status)).To(Succeed())
}

func (f *fakeAPIServer) listPods(writer http.ResponseWriter, request *http.Request) {
	selector, err := labels.Parse(request.URL.Query().Get("labelSelector"))
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	list := &corev1.PodList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}, Items: []corev1.Pod{}}
	for _, object := range f.objects {
		if pod, ok := object.(*corev1.Pod); ok && pod.Namespace == request.PathValue("namespace") && selector.Matches(labels.Set(pod.Labels)) {
			list.Items = append(list.Items, *pod)
		}
	}
	writeJSON(writer, list)
}

// portForward speaks the port-forward protocol, splicing each forwarded
// connection's data stream to the forwarded address.
func (f *fakeAPIServer) portForward(writer http.ResponseWriter, request *http.Request) {
	defer GinkgoRecover()
	f.mutex.Lock()
	f.forwards = append(f.forwards, request.Method+" "+request.PathValue("namespace")+"/"+request.PathValue("name"))
	f.mutex.Unlock()
	if request.Method != http.MethodPost {
		http.Error(writer, "websocket port-forward is not supported", http.StatusBadRequest)
		return
	}
	if _, err := streamhttp.Handshake(request, writer, []string{"portforward.k8s.io"}); err != nil {
		return
	}
	streams := make(chan streamhttp.Stream)
	connection := spdy.NewResponseUpgrader().UpgradeResponse(writer, request, func(stream streamhttp.Stream, _ <-chan struct{}) error {
		streams <- stream
		return nil
	})
	if connection == nil {
		return
	}
	defer func() { _ = connection.Close() }()
	errorStreams := map[string]streamhttp.Stream{}
	for {
		select {
		case <-connection.CloseChan():
			return
		case stream := <-streams:
			id := stream.Headers().Get(corev1.PortForwardRequestIDHeader)
			if stream.Headers().Get(corev1.StreamType) == corev1.StreamTypeError {
				errorStreams[id] = stream
				continue
			}
			go f.splice(stream, errorStreams[id])
		}
	}
}

func (f *fakeAPIServer) splice(data, errors streamhttp.Stream) {
	defer GinkgoRecover()
	defer func() { _ = errors.Close() }()
	defer func() { _ = data.Close() }()
	backend, err := (&net.Dialer{}).Dial("tcp", f.forwarded)
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = backend.Close() }()
	go func() {
		_, _ = io.Copy(backend, data)
		_ = backend.Close()
	}()
	_, _ = io.Copy(data, backend)
}

func (f *fakeAPIServer) observed() (forwards, tokens []string) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return append([]string{}, f.forwards...), append([]string{}, f.tokens...)
}

func writeJSON(writer http.ResponseWriter, object any) {
	defer GinkgoRecover()
	writer.Header().Set("Content-Type", "application/json")
	Expect(json.NewEncoder(writer).Encode(object)).To(Succeed())
}

// newConnectProxy returns the URL of an HTTP proxy that tunnels CONNECT
// requests to target and refuses every other request.
func newConnectProxy(target string) string {
	GinkgoHelper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer GinkgoRecover()
		if request.Method != http.MethodConnect || request.Host != target {
			http.Error(writer, "proxy refuses "+request.Host, http.StatusForbidden)
			return
		}
		backend, err := (&net.Dialer{}).DialContext(request.Context(), "tcp", target)
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = backend.Close() }()
		connection, buffered, err := http.NewResponseController(writer).Hijack()
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = connection.Close() }()
		_, _ = connection.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() {
			_, _ = io.Copy(backend, buffered)
			_ = backend.Close()
		}()
		_, _ = io.Copy(connection, backend)
	}))
	DeferCleanup(server.Close)
	return server.URL
}

// newDiagnosticsServer serves handler over TLS, as the operator's diagnostics
// endpoint does.
func newDiagnosticsServer(handler http.Handler) *httptest.Server {
	GinkgoHelper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	DeferCleanup(server.Close)
	return server
}
