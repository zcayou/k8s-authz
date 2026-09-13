package cli_test

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/model"
)

var _ = Describe("explain", func() {
	It("uses the fixed evaluator and reports the normalized principal", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		snapshotPath := writeExport(directory, time.Unix(2_000_000_000, 123), new(explanationFixture("empty")))
		code, stdout, stderr := execute(ctx, "", "explain", "--endpoint", "fleet", "--sar", writeReview(directory), "--snapshot", snapshotPath, "-o", "json")
		Expect(code).To(Equal(0), stderr)
		var report explanationReport
		Expect(json.Unmarshal(stdout, &report)).To(Succeed())
		Expect(report.Result).To(Equal(model.Result("Allow")))
		Expect(report.Code).To(Equal("PolicyAllowed"))
		Expect(report.Principal.User).To(Equal("alice"))
		Expect(report.Contributions).To(ConsistOf(HaveField("ContextID", "allow-context")))
		Expect(report.Exclusions).To(ConsistOf(HaveField("Path", HaveLen(1))))
		Expect(report.Issues).To(BeEmpty())
	})

	It("reports an authoritative failure answered with the endpoint's whenEvaluationFails", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		snapshotPath := writeExport(directory, time.Unix(2_000_000_000, 0), new(explanationFixture("broken")))
		code, stdout, stderr := execute(ctx, "", "explain", "--endpoint", "fleet", "--sar", writeReview(directory), "--snapshot", snapshotPath, "-o", "json")
		Expect(code).To(Equal(0), stderr)
		var report explanationReport
		Expect(json.Unmarshal(stdout, &report)).To(Succeed())
		Expect(report.Result).To(Equal(model.Result("Deny")))
		Expect(report.Code).To(Equal("EvaluationError"))
		Expect(report.EvaluationError).To(Equal("authoritative policy unavailable"))
		Expect(report.Issues).To(ConsistOf(And(HaveField("ID", "broken"), HaveField("Reason", model.ReasonMissingReference))))
	})

	It("reports when the snapshot it explains was exported", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		snapshotPath := writeExport(directory, time.Unix(10, 0), new(explanationFixture("empty")))
		code, stdout, stderr := execute(ctx, "", "explain", "--endpoint", "fleet", "--sar", writeReview(directory), "--snapshot", snapshotPath, "-o", "json")
		Expect(code).To(Equal(0), stderr)
		var report explanationReport
		Expect(json.Unmarshal(stdout, &report)).To(Succeed())
		Expect(report.ExportedAt).To(BeTemporally("==", time.Unix(10, 0)))
		Expect(report.Result).To(Equal(model.Result("Allow")))
	})

	It("reports whether each condition of the reached contributions held", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		held := conditionalExplanationFixture("package condition\nallow if input.request.resourceAttributes.namespace == \"tenant\"\n")
		snapshotPath := writeExport(directory, time.Unix(10, 0), &held)
		code, stdout, stderr := execute(ctx, "", "explain", "--endpoint", "fleet", "--sar", writeReview(directory), "--snapshot", snapshotPath, "-o", "json")
		Expect(code).To(Equal(0), stderr)
		var report explanationReport
		Expect(json.Unmarshal(stdout, &report)).To(Succeed())
		id := slices.Collect(maps.Keys(held.Conditions))[0]
		Expect(report.Result).To(Equal(model.Result("Allow")))
		Expect(report.Contributions).To(ConsistOf(HaveField("ConditionIDs", []string{id})))
		Expect(report.Conditions).To(Equal(map[string]bool{id: true}))

		code, text, stderr := execute(ctx, "", "explain", "--endpoint", "fleet", "--sar", writeReview(directory), "--snapshot", snapshotPath)
		Expect(code).To(Equal(0), stderr)
		Expect(string(text)).To(ContainSubstring(" conditions=" + id + ":true\n"))

		failed := conditionalExplanationFixture("package condition\nallow if input.request.resourceAttributes.namespace == \"other\"\n")
		snapshotPath = writeExport(directory, time.Unix(10, 0), &failed)
		code, stdout, stderr = execute(ctx, "", "explain", "--endpoint", "fleet", "--sar", writeReview(directory), "--snapshot", snapshotPath, "-o", "json")
		Expect(code).To(Equal(0), stderr)
		var refused explanationReport
		Expect(json.Unmarshal(stdout, &refused)).To(Succeed())
		Expect(refused.Result).To(Equal(model.Result("NoOpinion")))
		Expect(refused.Conditions).To(Equal(map[string]bool{slices.Collect(maps.Keys(failed.Conditions))[0]: false}))
	})

	It("refuses an export from a pod between a conditions module and a state push", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		state := explanationFixture("empty")
		snapshotPath := filepath.Join(directory, "snapshot.json")
		Expect(os.WriteFile(snapshotPath, exportWithModule(time.Unix(10, 0), "sha256:newer", &state), 0o600)).To(Succeed())
		code, stdout, stderr := execute(ctx, "", "explain", "--endpoint", "fleet", "--sar", writeReview(directory), "--snapshot", snapshotPath)
		Expect(code).To(Equal(2))
		Expect(stdout).To(BeEmpty())
		Expect(stderr).To(ContainSubstring("between a conditions module and a state push"))
	})

	It("reports an export without installed policy", func(ctx SpecContext) {
		directory := GinkgoT().TempDir()
		snapshotPath := writeExport(directory, time.Unix(10, 0), nil)
		code, stdout, stderr := execute(ctx, "", "explain", "--endpoint", "fleet", "--sar", writeReview(directory), "--snapshot", snapshotPath)
		Expect(code).To(Equal(2))
		Expect(stdout).To(BeEmpty())
		Expect(stderr).To(ContainSubstring("no installed policy"))
	})

	It("refuses state another evaluator compiled", func(ctx SpecContext) {
		state := explanationFixture("empty")
		state.EvaluatorID = "another-evaluator"
		directory := GinkgoT().TempDir()
		snapshotPath := writeExport(directory, time.Unix(10, 0), &state)
		code, stdout, stderr := execute(ctx, "", "explain", "--endpoint", "fleet", "--sar", writeReview(directory), "--snapshot", snapshotPath)
		Expect(code).To(Equal(2))
		Expect(stdout).To(BeEmpty())
		Expect(stderr).To(ContainSubstring(`compiled by evaluator "another-evaluator"`))
	})

	DescribeTable("rejects inconsistent inputs before reading anything", func(ctx SpecContext, message string, args ...string) {
		code, stdout, stderr := execute(ctx, "", append([]string{"explain"}, args...)...)
		Expect(code).To(Equal(2))
		Expect(stdout).To(BeEmpty())
		Expect(stderr).To(ContainSubstring(message))
	},
		Entry("no endpoint", "endpoint", "--sar", "sar.json", "--snapshot", "snapshot.json"),
		Entry("no snapshot source", "accepts 1 arg", "--endpoint", "fleet", "--sar", "sar.json"),
		Entry("a snapshot file and a pod", "none of the others", "--endpoint", "fleet", "--sar", "sar.json", "--snapshot", "snapshot.json", "--pod", "engine-one"),
		Entry("a snapshot file and an operator namespace", "none of the others", "--endpoint", "fleet", "--sar", "sar.json", "--snapshot", "snapshot.json", "--operator-namespace", "operators"),
		Entry("a snapshot file with a service", "unknown command", "authz", "--endpoint", "fleet", "--sar", "sar.json", "--snapshot", "snapshot.json"),
		Entry("a connected read without a service", "accepts 1 arg", "--endpoint", "fleet", "--sar", "sar.json", "--pod", "engine-one"),
		Entry("standard input twice", "standard input", "--endpoint", "fleet", "--sar", "-", "--snapshot", "-"),
	)
})
