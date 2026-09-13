package resources_test

import (
	"bytes"
	"encoding/json"

	. "github.com/onsi/gomega"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
)

const runtimeKindLabel = "authorization.zctx.io/runtime-kind"

func podOverride(data string) *api.PodTemplateOverride {
	return decodeOverride[api.PodTemplateOverride](data)
}

func serviceOverride(data string) *api.ServiceTemplateOverride {
	return decodeOverride[api.ServiceTemplateOverride](data)
}

func decodeOverride[T any](data string) *T {
	decoder := json.NewDecoder(bytes.NewReader([]byte(data)))
	decoder.DisallowUnknownFields()
	result := new(T)
	ExpectWithOffset(2, decoder.Decode(result)).To(Succeed())
	return result
}
