//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authorizationv1 "k8s.io/api/authorization/v1"

	"github.com/zcayou/k8s-authz/test/utils"
)

const decisionLogType = "openpolicyagent.org/decision_logs"

var _ = Describe("OPA decision logging", func() {
	It("emits a masked stock console event for endpoint decisions alone", func(ctx SpecContext) {
		fixture := startEngineFixture(ctx, true)
		fixture.install(ctx, secretProhibitionProgram())

		const (
			principalSentinel = "principal-must-not-appear"
			uidSentinel       = "uid-must-not-appear"
			groupSentinel     = "group-must-not-appear"
			extraKeySentinel  = "extra-key-must-not-appear"
			extraSentinel     = "extra-value-must-not-appear"
			secretSentinel    = "secret-name-must-not-appear"
			namespaceSentinel = "secret-namespace-must-not-appear"
		)
		review := utils.SubjectAccessReview(principalSentinel, "get", "secrets", namespaceSentinel)
		review.Spec.UID = uidSentinel
		review.Spec.Groups = []string{groupSentinel}
		review.Spec.Extra = map[string]authorizationv1.ExtraValue{extraKeySentinel: {extraSentinel}}
		review.Spec.ResourceAttributes.Name = secretSentinel
		result := decode(fixture.review(ctx, fixture.client(fixture.caller(utils.CallerCommonName)), review))
		Expect(result.Status.Allowed).To(BeFalse())
		Expect(result.Status.Denied).To(BeFalse())
		Expect(result.Status.Reason).NotTo(BeEmpty())

		// The installation's management reads are dropped, so the decision
		// is the only event.
		Eventually(func() []map[string]any {
			return decisionLogEntries(fixture.output())
		}, 10*time.Second).Should(ConsistOf(HaveKeyWithValue("path", "authz/endpoints/cluster/decision")), func() string { return string(fixture.output()) })
		event := decisionLogEntries(fixture.output())[0]
		Expect(event).To(HaveKeyWithValue("type", decisionLogType))
		Expect(event).To(HaveKey("decision_id"))
		Expect(event["decision_id"]).NotTo(BeEmpty())
		Expect(event).To(HaveKey("timestamp"))
		Expect(event).NotTo(HaveKey("input"))
		erased, ok := event["erased"].([]any)
		Expect(ok).To(BeTrue())
		Expect(erased).To(ContainElement("/input"))
		loggedResult, ok := event["result"].(map[string]any)
		Expect(ok).To(BeTrue())
		Expect(loggedResult).NotTo(HaveKey("spec"))
		Expect(loggedResult).NotTo(HaveKey("metadata"))
		Expect(loggedResult).To(HaveKey("status"))
		Expect(loggedResult["status"]).To(SatisfyAll(
			HaveKeyWithValue("allowed", false),
			HaveKeyWithValue("denied", false),
			HaveKey("reason"),
		))
		Expect(event).NotTo(HaveKey("request_context"))
		encoded, err := json.Marshal(event)
		Expect(err).NotTo(HaveOccurred())
		for _, sentinel := range []string{principalSentinel, uidSentinel, groupSentinel, extraKeySentinel, extraSentinel, secretSentinel, namespaceSentinel} {
			Expect(encoded).NotTo(ContainSubstring(sentinel))
			Expect(fixture.output()).NotTo(ContainSubstring(sentinel))
		}
	}, SpecTimeout(40*time.Second))
})

func decisionLogEntries(output []byte) []map[string]any {
	entries := make([]map[string]any, 0, 1)
	for line := range bytes.Lines(output) {
		var entry map[string]any
		if json.Unmarshal(bytes.TrimSpace(line), &entry) == nil && entry["type"] == decisionLogType {
			entries = append(entries, entry)
		}
	}
	return entries
}
