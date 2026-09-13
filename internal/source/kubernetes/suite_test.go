package kubernetes_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestKubernetesSource(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Kubernetes Source Reader Suite")
}
