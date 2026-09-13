package operator

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"

	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/resources"
)

// Options carries the operator's command-line configuration. Certificate
// paths name directories holding tls.crt and tls.key; CA paths name a PEM
// bundle file.
type Options struct {
	// ControlNamespaces restricts the watched AuthorizationServices
	// and PolicySources. Empty watches every namespace.
	ControlNamespaces      []string
	EngineImage            string
	EngineDecisionLogs     bool
	ManagementCertPath     string
	ManagementCAPath       string
	DiagnosticsBindAddress string
	DiagnosticsCertPath    string
	// RemediationAfter is how long pushes to an engine pod may keep failing
	// before the leader evicts it.
	RemediationAfter time.Duration
}

// BindFlags registers the operator flags on flags.
func (o *Options) BindFlags(flags *flag.FlagSet) {
	flags.Func("control-namespaces",
		"Comma-separated namespaces whose AuthorizationServices and PolicySources are reconciled. Empty reconciles all namespaces.",
		o.setControlNamespaces)
	flags.StringVar(&o.EngineImage, "engine-image", engine.DefaultImage, "Stock OPA engine image, pinned by digest.")
	flags.BoolVar(&o.EngineDecisionLogs, "engine-decision-logs", false, "Enable decision logs in every engine.")
	flags.StringVar(&o.ManagementCertPath, "management-cert-path", "",
		"Directory holding the tls.crt and tls.key the operator presents to engines.")
	flags.StringVar(&o.ManagementCAPath, "management-ca-path", "",
		"PEM file holding the CA bundle that issues the operator's management certificate.")
	flags.StringVar(&o.DiagnosticsBindAddress, "diagnostics-bind-address", ":9443", "Address the diagnostics endpoint binds to.")
	flags.StringVar(&o.DiagnosticsCertPath, "diagnostics-cert-path", "",
		"Directory holding the tls.crt and tls.key the diagnostics endpoint serves.")
	flags.DurationVar(&o.RemediationAfter, "remediation-after", 2*time.Minute,
		"How long pushes to an engine pod may keep failing before it is evicted.")
}

func (o *Options) setControlNamespaces(value string) error {
	o.ControlNamespaces = nil
	if value == "" {
		return nil
	}
	for name := range strings.SplitSeq(value, ",") {
		if problems := utilvalidation.IsDNS1123Label(name); len(problems) != 0 {
			return fmt.Errorf("namespace %q: %s", name, strings.Join(problems, "; "))
		}
		o.ControlNamespaces = append(o.ControlNamespaces, name)
	}
	slices.Sort(o.ControlNamespaces)
	o.ControlNamespaces = slices.Compact(o.ControlNamespaces)
	return nil
}

// Validate reports missing required flags, an engine image that is not
// pinned by digest and a negative remediation delay.
func (o *Options) Validate() error {
	var errs []error
	for _, required := range []struct{ name, value string }{
		{"management-cert-path", o.ManagementCertPath},
		{"management-ca-path", o.ManagementCAPath},
		{"diagnostics-bind-address", o.DiagnosticsBindAddress},
		{"diagnostics-cert-path", o.DiagnosticsCertPath},
	} {
		if required.value == "" {
			errs = append(errs, fmt.Errorf("--%s is required", required.name))
		}
	}
	if err := resources.ValidateImage(o.EngineImage); err != nil {
		errs = append(errs, fmt.Errorf("--engine-image: %w", err))
	}
	if o.RemediationAfter < 0 {
		errs = append(errs, errors.New("--remediation-after must not be negative"))
	}
	return errors.Join(errs...)
}

func certificateFiles(directory string) (certificate, key string) {
	return filepath.Join(directory, corev1.TLSCertKey), filepath.Join(directory, corev1.TLSPrivateKeyKey)
}
