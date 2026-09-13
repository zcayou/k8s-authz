package resources_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/resources"
)

var _ = Describe("Runtime resource names", func() {
	It("names the owned objects after the service", func() {
		Expect(resources.Name("authorization-service")).To(Equal("authz-authorization-service"))
	})

	It("verifies engines as the listener Service's DNS name", func() {
		Expect(resources.ServerName("control", "authorization-service")).To(Equal("authz-authorization-service.control.svc"))
	})
})
