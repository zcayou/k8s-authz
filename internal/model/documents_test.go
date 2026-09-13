package model_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
)

var _ = Describe("Digests", func() {
	It("digest the JSON encoding, preserving large integers and list order", func() {
		value := struct {
			Z uint64   `json:"z"`
			B []string `json:"b"`
			M map[string]int64
		}{Z: math.MaxUint64, B: []string{"second", "first"}, M: map[string]int64{"y": math.MaxInt64, "a": 1}}
		encoded, err := json.Marshal(value)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(encoded)).To(Equal(`{"z":18446744073709551615,"b":["second","first"],"M":{"a":1,"y":9223372036854775807}}`))
		sum := sha256.Sum256(append(encoded, '\n'))
		Expect(model.Digest(value)).To(Equal(hex.EncodeToString(sum[:])))
	})

	It("orders references by every field", func() {
		source := model.SourceKey{Namespace: "control", Name: "local"}
		first := model.Reference{Source: source, Group: api.GroupVersion.Group, Kind: model.KindPolicy, Namespace: "a", Name: "same"}
		second := first
		second.Namespace = "b"
		third := first
		third.Kind = model.KindPolicySet
		references := []model.Reference{third, second, first, second}
		model.SortReferences(references)
		Expect(references).To(Equal([]model.Reference{first, second, second, third}))
	})
})
