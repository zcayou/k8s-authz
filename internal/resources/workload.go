package resources

import (
	"errors"
	"fmt"
	"path"
	"strconv"

	"github.com/distribution/reference"
	corev1 "k8s.io/api/core/v1"
)

const (
	ContainerName            = "opa"
	HTTPSPortName            = "https"
	DiagnosticPortName       = "diagnostic"
	EnginePort         int32 = 8181
	DiagnosticPort     int32 = 8182
	DefaultServicePort int32 = 443
	EnginePath               = "/opa"
	// EngineDirectory is where the engine ConfigMap is mounted.
	EngineDirectory = "/engine"
	// TLSDirectory is where the serving certificate Secret is mounted.
	TLSDirectory = "/tls"
)

// The engine ConfigMap's keys besides its Rego modules.
const (
	ConfigKey    = "config.yaml"
	BootstrapKey = "bootstrap.json"
	CABundleKey  = "ca.crt"
)

const (
	policyDirectory = "policy"
	dataDirectory   = "data"
)

// Layout is where an engine listens and finds its files.
type Layout struct {
	Address           string
	DiagnosticAddress string
	EngineDirectory   string
	TLSDirectory      string
}

// PodLayout is the layout of every engine pod.
var PodLayout = Layout{
	Address:           ":" + strconv.Itoa(int(EnginePort)),
	DiagnosticAddress: "http://:" + strconv.Itoa(int(DiagnosticPort)),
	EngineDirectory:   EngineDirectory,
	TLSDirectory:      TLSDirectory,
}

// Arguments returns the stock OPA command line for the layout. OPA serves TLS
// on Address and plaintext on DiagnosticAddress, requires a client certificate
// that chains to the CA bundle, authorizes every request through system.authz
// and reloads the certificate, key and CA bundle in place. It never checks
// for a newer OPA release. It loads only the policy and data directories, so
// a projected volume's hidden entries at its root are never read,
// and the bootstrap lands under data.bootstrap by its directory.
func (l Layout) Arguments() []string {
	return []string{
		"run", "--server",
		"--skip-version-check",
		"--addr=" + l.Address,
		"--diagnostic-addr=" + l.DiagnosticAddress,
		"--authentication=tls",
		"--authorization=basic",
		"--tls-cert-file=" + path.Join(l.TLSDirectory, corev1.TLSCertKey),
		"--tls-private-key-file=" + path.Join(l.TLSDirectory, corev1.TLSPrivateKeyKey),
		"--tls-ca-cert-file=" + path.Join(l.EngineDirectory, CABundleKey),
		"--config-file=" + path.Join(l.EngineDirectory, ConfigKey),
		path.Join(l.EngineDirectory, policyDirectory),
		path.Join(l.EngineDirectory, dataDirectory),
	}
}

// ItemPath returns the path, below EngineDirectory, of the engine ConfigMap's
// key. Every key other than ConfigKey, BootstrapKey and CABundleKey is a Rego
// module.
func ItemPath(key string) string {
	switch key {
	case ConfigKey, CABundleKey:
		return key
	case BootstrapKey:
		return path.Join(dataDirectory, "bootstrap", "data.json")
	default:
		return path.Join(policyDirectory, key)
	}
}

// ValidateImage accepts an image reference pinned by digest.
func ValidateImage(image string) error {
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return fmt.Errorf("parse engine image: %w", err)
	}
	if _, pinned := named.(reference.Digested); !pinned {
		return errors.New("engine image must be pinned by digest")
	}
	return nil
}
