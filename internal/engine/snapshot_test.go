package engine_test

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
)

var _ = Describe("Complete policy snapshots", func() {
	It("encodes deterministic content and returns to the same revision for A to B to A", func() {
		content, _, err := engine.FinalizeContent(emptyProgram(), "service-1")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(content.Revision)).To(MatchRegexp(`^sha256:[0-9a-f]{64}$`))
		changed := emptyProgram()
		changed.Endpoints["cluster"] = model.EndpointProgram{Name: "cluster", WhenEvaluationFails: "NoOpinion", Authorities: []model.AuthorityProgram{}}
		other, _, err := engine.FinalizeContent(changed, "service-1")
		Expect(err).NotTo(HaveOccurred())
		Expect(other.Revision).NotTo(Equal(content.Revision))
		restored, _, err := engine.FinalizeContent(emptyProgram(), "service-1")
		Expect(err).NotTo(HaveOccurred())
		Expect(restored).To(Equal(content))
	})
	It("binds the program to its service in the revision", func() {
		first, _, err := engine.FinalizeContent(emptyProgram(), "service-1")
		Expect(err).NotTo(HaveOccurred())
		second, _, err := engine.FinalizeContent(emptyProgram(), "another-service")
		Expect(err).NotTo(HaveOccurred())
		Expect(second.ServiceUID).To(Equal(model.ServiceUID("another-service")))
		Expect(second.Revision).NotTo(Equal(first.Revision))
	})
	It("generates the conditions module and addresses the state by its digest", func() {
		empty, module, err := engine.FinalizeContent(emptyProgram(), "service-1")
		Expect(err).NotTo(HaveOccurred())
		generated, err := condition.Generate(nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(module).To(Equal(generated))
		Expect(empty.ConditionsDigest).To(Equal(generated.Digest))

		program := emptyProgram()
		checked, err := condition.Check("package condition\nallow if input.request.nonResourceAttributes.path == \"/healthz\"\n")
		Expect(err).NotTo(HaveOccurred())
		program.Conditions = map[string]model.Condition{checked.ID: checked}
		conditional, module, err := engine.FinalizeContent(program, "service-1")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(module.Source)).To(ContainSubstring("c_" + checked.ID + "_allow"))
		Expect(conditional.ConditionsDigest).To(Equal(module.Digest))
		Expect(conditional.ConditionsDigest).NotTo(Equal(empty.ConditionsDigest))
		Expect(conditional.Revision).NotTo(Equal(empty.Revision))
	})
	It("bounds the conditions module", func() {
		program := emptyProgram()
		program.Conditions = map[string]model.Condition{}
		for index := range 20 {
			checked, err := condition.Check(fmt.Sprintf("package condition\nallow if input.request.nonResourceAttributes.path == %q\n", strings.Repeat("a", 60000)+strconv.Itoa(index)))
			Expect(err).NotTo(HaveOccurred())
			program.Conditions[checked.ID] = checked
		}
		Expect(engine.FinalizeContent(program, "service-1")).Error().To(MatchError(model.ErrLimit))
	})
	It("bounds the entire pushed document, revision included", func() {
		padded := func(length int64) model.PreparedRevision {
			program := emptyProgram()
			program.Issues["padding"] = model.ProgramIssue{Issue: model.Issue{Message: strings.Repeat("a", int(length))}}
			return program
		}
		unpadded, _, err := engine.FinalizeContent(padded(0), "service-1")
		Expect(err).NotTo(HaveOccurred())
		encoded, err := json.Marshal(unpadded)
		Expect(err).NotTo(HaveOccurred())
		room := engine.MaxContentBytes - int64(len(encoded))

		largest, _, err := engine.FinalizeContent(padded(room), "service-1")
		Expect(err).NotTo(HaveOccurred())
		encoded, err = json.Marshal(largest)
		Expect(err).NotTo(HaveOccurred())
		Expect(int64(len(encoded))).To(Equal(engine.MaxContentBytes))
		Expect(engine.FinalizeContent(padded(room+1), "service-1")).Error().To(MatchError(model.ErrLimit))
	})
})

func emptyProgram() model.PreparedRevision {
	GinkgoHelper()
	program := model.PreparedRevision{
		Endpoints:  map[string]model.EndpointProgram{"cluster": {Name: "cluster", WhenEvaluationFails: "Deny", Callers: []string{"kube-apiserver"}, Authorities: []model.AuthorityProgram{}}},
		Predicates: map[string]model.Matcher{}, Contributions: map[string]model.Contribution{}, Diagrams: map[string]model.Diagram{}, Issues: map[string]model.ProgramIssue{},
	}
	return program
}
