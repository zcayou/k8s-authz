package cli_test

import (
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCLI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CLI Suite")
}

// The commands' kubeconfig loading never reads the developer's own.
var _ = BeforeSuite(func() {
	GinkgoT().Setenv("KUBECONFIG", filepath.Join(GinkgoT().TempDir(), "absent"))
})
