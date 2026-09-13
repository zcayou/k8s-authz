package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/cli"
	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
)

// validationReport decodes the JSON report of the validate commands.
type validationReport struct {
	Valid       bool         `json:"valid"`
	Documents   int          `json:"documents"`
	Diagnostics []diagnostic `json:"diagnostics"`
}

type diagnostic struct {
	File      string            `json:"file"`
	Source    *model.SourceKey  `json:"source"`
	FieldPath string            `json:"fieldPath"`
	Severity  api.IssueSeverity `json:"severity"`
	Reason    model.IssueReason `json:"reason"`
	Message   string            `json:"message"`
	Endpoint  string            `json:"endpoint"`
}

// explanationReport decodes the JSON report of explain.
type explanationReport struct {
	ExportedAt      time.Time       `json:"exportedAt"`
	Result          model.Result    `json:"result"`
	Code            string          `json:"code"`
	EvaluationError string          `json:"evaluationError"`
	Principal       model.Principal `json:"principal"`
	Contributions   []struct {
		ContextID    string   `json:"contextID"`
		ConditionIDs []string `json:"conditionIDs"`
	} `json:"contributions"`
	Exclusions []struct {
		Path []model.DocumentKey `json:"path"`
	} `json:"exclusions"`
	Issues []struct {
		ID     string            `json:"id"`
		Reason model.IssueReason `json:"reason"`
	} `json:"issues"`
	Conditions map[string]bool `json:"conditions"`
}

// execute runs the k8s-authz command with args and stdin, and returns its
// exit code, standard output and standard error.
func execute(ctx context.Context, stdin string, args ...string) (int, []byte, string) {
	command := cli.NewCommand()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	command.SetArgs(args)
	command.SetIn(strings.NewReader(stdin))
	command.SetOut(stdout)
	command.SetErr(stderr)
	code := cli.Execute(ctx, command)
	return code, stdout.Bytes(), stderr.String()
}

// explanationFixture is installed state whose authority records its
// authoritative failures in the named diagram.
func explanationFixture(authoritativeFailures string) model.ContentRevision {
	GinkgoHelper()
	return finalizeExplanation(explanationProgram(authoritativeFailures))
}

// conditionalExplanationFixture is explanationFixture("empty") whose grant
// carries the condition source.
func conditionalExplanationFixture(source string) model.ContentRevision {
	GinkgoHelper()
	program := explanationProgram("empty")
	checked, err := condition.Check(source)
	Expect(err).NotTo(HaveOccurred())
	program.Conditions = map[string]model.Condition{checked.ID: checked}
	allow := program.Contributions["allow"]
	allow.ConditionIDs = []string{checked.ID}
	program.Contributions["allow"] = allow
	return finalizeExplanation(program)
}

func explanationProgram(authoritativeFailures string) model.PreparedRevision {
	GinkgoHelper()
	all := model.AllPrincipals()
	program := model.PreparedRevision{
		Endpoints:  map[string]model.EndpointProgram{},
		Predicates: map[string]model.Matcher{"all": all}, Contributions: map[string]model.Contribution{}, Diagrams: map[string]model.Diagram{}, Issues: map[string]model.ProgramIssue{}, Exclusions: map[string]model.ExclusionProof{},
	}
	program.Contributions["allow"] = model.Contribution{ID: "allow", Effect: model.EffectAllow, PrincipalIDs: []string{"all"}, ContextID: "allow-context"}
	program.Issues["broken"] = model.ProgramIssue{Issue: model.Issue{Severity: api.IssueSeverityError, Reason: model.ReasonMissingReference, Message: "a prohibition is unavailable", ContextID: "broken-context"}, PrincipalIDs: []string{"all"}}
	program.Diagrams["allow"] = labelledUniversal("allow")
	program.Diagrams["broken"] = labelledUniversal("broken")
	program.Diagrams["empty"] = model.NewArena(2).Snapshot(0)
	program.Diagrams["excluded"] = labelledUniversal("excluded")
	program.Exclusions["excluded"] = model.ExclusionProof{ID: "excluded", Endpoint: "fleet", Authority: "oidc", Effect: model.EffectAllow, DiagramID: "excluded", PrincipalIDs: []string{"all"}, ContextID: "excluded-context", Path: []model.DocumentKey{{Group: api.GroupVersion.Group, Kind: model.KindPolicy, Namespace: "tenant", Name: "limited"}}}
	program.Endpoints["fleet"] = model.EndpointProgram{Name: "fleet", WhenEvaluationFails: "Deny", Callers: []string{"kube-apiserver"}, Authorities: []model.AuthorityProgram{{Name: "oidc", MatcherID: "all", Fallback: "NoOpinion", ProhibitionDiagramID: "empty", IndependentAllowDiagramIDs: []string{"allow"}, AuthoritativeFailureDiagramID: authoritativeFailures}}}
	return program
}

func finalizeExplanation(program model.PreparedRevision) model.ContentRevision {
	GinkgoHelper()
	content, _, err := engine.FinalizeContent(program, "service-uid")
	Expect(err).NotTo(HaveOccurred())
	return content
}

// export encodes the diagnostics endpoint's export of state, read at exportedAt
// from a pod serving state's conditions module.
func export(exportedAt time.Time, state *model.ContentRevision) []byte {
	GinkgoHelper()
	var digest string
	if state != nil {
		digest = state.ConditionsDigest
	}
	return exportWithModule(exportedAt, digest, state)
}

// exportWithModule encodes the export of state from a pod serving
// the conditions module whose digest is conditionsDigest.
func exportWithModule(exportedAt time.Time, conditionsDigest string, state *model.ContentRevision) []byte {
	GinkgoHelper()
	data, err := json.Marshal(struct {
		ExportedAt       time.Time              `json:"exportedAt"`
		ConditionsDigest string                 `json:"conditionsDigest"`
		State            *model.ContentRevision `json:"state"`
	}{exportedAt, conditionsDigest, state})
	Expect(err).NotTo(HaveOccurred())
	return data
}

func labelledUniversal(id string) model.Diagram {
	GinkgoHelper()
	arena := model.NewArena(3)
	root, err := arena.Label(1, id)
	Expect(err).NotTo(HaveOccurred())
	return arena.Snapshot(root)
}

// writeExport writes the export of state, read at exportedAt, to a file
// in directory and returns its path.
func writeExport(directory string, exportedAt time.Time, state *model.ContentRevision) string {
	GinkgoHelper()
	path := filepath.Join(directory, "snapshot.json")
	Expect(os.WriteFile(path, export(exportedAt, state), 0o600)).To(Succeed())
	return path
}

func writeReview(directory string) string {
	GinkgoHelper()
	path := filepath.Join(directory, "sar.json")
	Expect(os.WriteFile(path, []byte(`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"alice","resourceAttributes":{"verb":"get","resource":"pods","version":"v1","namespace":"tenant"}}}`), 0o600)).To(Succeed())
	return path
}
