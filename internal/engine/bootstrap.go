package engine

import (
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"strings"
	"sync"

	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/program"
)

//go:embed assets/*.rego
var evaluatorAssets embed.FS

// Bootstrap is the document an engine starts from, loaded under data.bootstrap.
// It binds the pod to its service and evaluator, and names the operator
// identity allowed to manage it.
type Bootstrap struct {
	ServiceUID  model.ServiceUID `json:"serviceUID"`
	EvaluatorID string           `json:"evaluatorID"`
	Management  Management       `json:"management"`
}

// Management authenticates the operator on the management paths. Its client
// certificate must chain to one of Roots and carry the Common Name Identity.
// The TLS handshake verifies clients against a pool shared with the webhook
// callers, so system.authz verifies the roots again.
type Management struct {
	Roots    []string `json:"roots"`
	Identity string   `json:"identity"`
}

// NewBootstrap returns the bootstrap of a service's engines. roots is the PEM
// bundle that issues the operator's client certificate, and identity is its
// Common Name.
func NewBootstrap(service model.ServiceUID, roots []byte, identity string) (Bootstrap, error) {
	bootstrap := Bootstrap{ServiceUID: service, EvaluatorID: EvaluatorID(), Management: Management{Identity: identity}}
	for block, rest := pem.Decode(roots); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			bootstrap.Management.Roots = append(bootstrap.Management.Roots, string(pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes})))
		}
	}
	if len(bootstrap.Management.Roots) == 0 {
		return Bootstrap{}, errors.New("management CA bundle holds no certificates")
	}
	if identity == "" {
		return Bootstrap{}, errors.New("management certificate has no Common Name")
	}
	return bootstrap, nil
}

// Modules returns the release-owned Rego modules every engine loads, by file
// name: the evaluator's and the Kubernetes program's. Policy documents
// contribute executable Rego only through the conditions module the operator
// pushes.
func Modules() map[string]string {
	return maps.Clone(modules())
}

// EvaluatorID identifies the evaluator: the runtime and the modules. An engine
// is ready only for state compiled for its evaluator.
var EvaluatorID = sync.OnceValue(func() string {
	return model.Digest(struct {
		Runtime string            `json:"runtime"`
		Modules map[string]string `json:"modules"`
	}{RuntimeVersion, modules()})
})

// modules reads the embedded modules. The files and the pattern are fixed
// at build time, so reading them can't fail.
var modules = sync.OnceValue(func() map[string]string {
	modules := map[string]string{}
	for _, assets := range []embed.FS{evaluatorAssets, program.Assets} {
		paths, err := fs.Glob(assets, "assets/*.rego")
		if err != nil {
			panic(fmt.Sprintf("list Rego modules: %v", err))
		}
		for _, path := range paths {
			data, err := assets.ReadFile(path)
			if err != nil {
				panic(fmt.Sprintf("read Rego module: %v", err))
			}
			modules[strings.TrimPrefix(path, "assets/")] = string(data)
		}
	}
	return modules
})
