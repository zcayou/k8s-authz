package engineclient_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestEngineClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Engine Client Suite")
}
