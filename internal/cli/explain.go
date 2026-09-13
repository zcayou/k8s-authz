package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
)

// explanationProof identifies one qualified path relevant to the request.
type explanationProof struct {
	ID           string              `json:"id"`
	Effect       model.Effect        `json:"effect"`
	ContextID    string              `json:"contextID"`
	Path         []model.DocumentKey `json:"path"`
	ConditionIDs []string            `json:"conditionIDs,omitempty"`
}

// explanationIssue is a bounded contextual failure retained by the program.
type explanationIssue struct {
	ID        string              `json:"id"`
	Reason    model.IssueReason   `json:"reason"`
	Message   string              `json:"message"`
	ContextID string              `json:"contextID,omitempty"`
	Path      []model.DocumentKey `json:"path,omitempty"`
}

// explanationReport explains one decision of an installed snapshot.
type explanationReport struct {
	ExportedAt          time.Time          `json:"exportedAt"`
	Endpoint            string             `json:"endpoint"`
	Authority           string             `json:"authority,omitempty"`
	Root                *model.Reference   `json:"root,omitempty"`
	ServiceUID          model.ServiceUID   `json:"serviceUID"`
	ContentRevision     model.RevisionID   `json:"contentRevision"`
	Result              model.Result       `json:"result"`
	Reason              string             `json:"reason"`
	Code                string             `json:"code"`
	EvaluationError     string             `json:"evaluationError,omitempty"`
	Principal           model.Principal    `json:"principal"`
	Contributions       []explanationProof `json:"contributions"`
	Prohibitions        []explanationProof `json:"prohibitions"`
	Exclusions          []explanationProof `json:"exclusions"`
	ExclusionsTruncated bool               `json:"exclusionsTruncated,omitempty"`
	Issues              []explanationIssue `json:"issues"`
	// Conditions maps each condition of every contribution the request reached
	// to whether it held.
	Conditions map[string]bool `json:"conditions"`
}

// snapshot is an export of the state installed on one engine pod, in the form
// the operator's diagnostics endpoint serves, with the digest of the conditions
// module the pod served. State is nil when the pod had none.
type snapshot struct {
	ExportedAt       time.Time              `json:"exportedAt"`
	ConditionsDigest string                 `json:"conditionsDigest"`
	State            *model.ContentRevision `json:"state"`
}

type explainOptions struct {
	connection        *connection
	endpoint          string
	sar               string
	snapshot          string
	pod               string
	operatorNamespace string
	export            string
	output            string
}

func newExplainCommand() *cobra.Command {
	options := &explainOptions{}
	command := &cobra.Command{
		Use:   "explain (NAME [--pod POD] | --snapshot FILE) --endpoint ENDPOINT --sar FILE",
		Short: "Evaluate and explain one immutable authorization snapshot",
		Long: `Explain evaluates a SubjectAccessReview against the snapshot installed on one
engine pod of the AuthorizationService NAME, or against a snapshot file saved
with --export-snapshot.

The installed snapshot is read from the operator's diagnostics endpoint,
through a port-forward to an operator pod that kube-apiserver opens with your
credentials. The endpoint authenticates the same credentials and requires get
on the service's authorizationservices/diagnostics subresource. Without --pod,
any ready engine pod of the service is read.`,
		Args: func(command *cobra.Command, args []string) error {
			if options.snapshot != "" {
				return cobra.NoArgs(command, args)
			}
			return cobra.ExactArgs(1)(command, args)
		},
		RunE: options.run,
	}
	flags := command.Flags()
	flags.StringVar(&options.endpoint, "endpoint", "", "authorization endpoint name")
	flags.StringVar(&options.sar, "sar", "", "raw SubjectAccessReview file or - for standard input")
	flags.StringVar(&options.snapshot, "snapshot", "", "exported installed snapshot file")
	flags.StringVar(&options.pod, "pod", "", "engine Pod of the service; defaults to any ready one")
	flags.StringVar(&options.operatorNamespace, "operator-namespace", defaultOperatorNamespace, "namespace the operator runs in")
	flags.StringVar(&options.export, "export-snapshot", "", "save the installed snapshot for offline explanation")
	options.connection = bindConnectionFlags(command)
	registerOutputFlag(command, &options.output)
	_ = command.MarkFlagRequired("endpoint")
	_ = command.MarkFlagRequired("sar")
	command.MarkFlagsMutuallyExclusive("snapshot", "pod")
	command.MarkFlagsMutuallyExclusive("snapshot", "operator-namespace")
	return command
}

func (o *explainOptions) run(command *cobra.Command, args []string) error {
	if err := checkOutput(o.output); err != nil {
		return err
	}
	if o.snapshot == "-" && o.sar == "-" {
		return errors.New("standard input cannot supply both --snapshot and --sar")
	}
	stdin := command.InOrStdin()
	data, err := o.readSnapshot(command.Context(), stdin, args)
	if err != nil {
		return err
	}
	var exported snapshot
	if err = json.Unmarshal(data, &exported); err != nil {
		return fmt.Errorf("decode snapshot: %w", err)
	}
	if exported.State == nil {
		return errors.New("engine pod has no installed policy")
	}
	// Between the two writes of a push, the pod's answers are neither its
	// state's nor the next one's.
	if exported.ConditionsDigest != exported.State.ConditionsDigest {
		return errors.New("engine pod is between a conditions module and a state push; explain it again")
	}
	rawSAR, err := readInput(stdin, o.sar, maxInputBytes)
	if err != nil {
		return err
	}
	evaluation, err := engine.EvaluateSnapshot(command.Context(), *exported.State, o.endpoint, rawSAR)
	if err != nil {
		return err
	}
	report := explainSnapshot(exported.ExportedAt, *exported.State, o.endpoint, evaluation)
	if o.export != "" {
		if err = writeFileAtomically(o.export, data, 0o600); err != nil {
			return err
		}
	}
	if err = writeExplanation(command.OutOrStdout(), o.output, report); err != nil {
		return fmt.Errorf("write explanation: %w", err)
	}
	return nil
}

// readSnapshot reads the snapshot export from --snapshot, or from
// the diagnostics endpoint.
func (o *explainOptions) readSnapshot(ctx context.Context, stdin io.Reader, args []string) ([]byte, error) {
	if o.snapshot != "" {
		return readInput(stdin, o.snapshot, engine.MaxExportBytes)
	}
	cluster, err := o.connection.connect()
	if err != nil {
		return nil, err
	}
	return readInstalledSnapshot(ctx, cluster, snapshotRequest{namespace: cluster.namespace, service: args[0], pod: o.pod, operatorNamespace: o.operatorNamespace})
}

func explainSnapshot(exportedAt time.Time, content model.ContentRevision, endpoint string, evaluation engine.SnapshotEvaluation) explanationReport {
	report := explanationReport{
		ExportedAt: exportedAt, Endpoint: endpoint, Authority: evaluation.Decision.Authority,
		ServiceUID: content.ServiceUID, ContentRevision: content.Revision,
		Result: evaluation.Decision.Result, Reason: evaluation.Decision.Reason, Code: evaluation.Decision.Code, EvaluationError: evaluation.Decision.EvaluationError,
		Principal: evaluation.Principal, Contributions: []explanationProof{}, Prohibitions: []explanationProof{}, Exclusions: []explanationProof{}, Issues: []explanationIssue{},
		ExclusionsTruncated: content.ExclusionsTruncated, Conditions: map[string]bool{},
	}
	maps.Copy(report.Conditions, evaluation.Conditions)
	for _, id := range evaluation.Decision.ContributionIDs {
		if contribution, exists := content.Contributions[id]; exists {
			if contribution.Effect == model.EffectDeny {
				report.Prohibitions = appendProof(report.Prohibitions, contributionProof(contribution))
			} else {
				report.Contributions = appendProof(report.Contributions, contributionProof(contribution))
			}
		}
	}
	endpointProgram := content.Endpoints[endpoint]
	index := slices.IndexFunc(endpointProgram.Authorities, func(authority model.AuthorityProgram) bool {
		return authority.Name == evaluation.Decision.Authority
	})
	issueIDs := map[string]bool{}
	if index >= 0 {
		authority := endpointProgram.Authorities[index]
		report.Root = new(authority.Root)
		for _, id := range evaluation.Terminals[authority.ProhibitionDiagramID] {
			if contribution, exists := content.Contributions[id]; exists {
				report.Prohibitions = appendProof(report.Prohibitions, contributionProof(contribution))
			}
		}
		for _, proof := range content.Exclusions {
			if proof.Endpoint == endpoint && proof.Authority == authority.Name && slices.Contains(evaluation.Terminals[proof.DiagramID], proof.ID) {
				report.Exclusions = append(report.Exclusions, explanationProof{ID: proof.ID, Effect: proof.Effect, ContextID: proof.ContextID, Path: slices.Clone(proof.Path)})
			}
		}
		for _, id := range evaluation.Decision.IssueIDs {
			issueIDs[id] = true
		}
		for _, id := range evaluation.Terminals[authority.AuthoritativeFailureDiagramID] {
			issueIDs[id] = true
		}
	}
	for id := range issueIDs {
		if issue, exists := content.Issues[id]; exists {
			report.Issues = append(report.Issues, explanationIssue{ID: id, Reason: issue.Reason, Message: issue.Message, ContextID: issue.ContextID, Path: slices.Clone(issue.Path)})
		}
	}
	slices.SortFunc(report.Contributions, compareProofs)
	slices.SortFunc(report.Prohibitions, compareProofs)
	slices.SortFunc(report.Exclusions, compareProofs)
	slices.SortFunc(report.Issues, func(a, b explanationIssue) int { return strings.Compare(a.ID, b.ID) })
	return report
}

func contributionProof(contribution model.Contribution) explanationProof {
	return explanationProof{ID: contribution.ID, Effect: contribution.Effect, ContextID: contribution.ContextID, Path: slices.Clone(contribution.Path), ConditionIDs: slices.Clone(contribution.ConditionIDs)}
}

func appendProof(proofs []explanationProof, proof explanationProof) []explanationProof {
	if slices.ContainsFunc(proofs, func(existing explanationProof) bool { return existing.ID == proof.ID }) {
		return proofs
	}
	return append(proofs, proof)
}

func compareProofs(a, b explanationProof) int {
	return strings.Compare(a.ID, b.ID)
}

func writeExplanation(writer io.Writer, output string, report explanationReport) error {
	if output == formatJSON {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(writer, "%s\n", data)
		return err
	}
	_, err := fmt.Fprintf(writer, "snapshot exported %s: %s (%s) endpoint=%s authority=%s content=%s\n", report.ExportedAt.Format(time.RFC3339Nano), report.Result, report.Code, report.Endpoint, report.Authority, report.ContentRevision)
	if err != nil {
		return err
	}
	for _, proof := range report.Contributions {
		if _, err = fmt.Fprintf(writer, "contribution %s effect=%s path=%d%s\n", proof.ID, proof.Effect, len(proof.Path), conditionOutcomes(proof.ConditionIDs, report.Conditions)); err != nil {
			return err
		}
	}
	for _, proof := range report.Prohibitions {
		if _, err = fmt.Fprintf(writer, "prohibition %s path=%d\n", proof.ID, len(proof.Path)); err != nil {
			return err
		}
	}
	for _, proof := range report.Exclusions {
		if _, err = fmt.Fprintf(writer, "exclusion %s path=%d\n", proof.ID, len(proof.Path)); err != nil {
			return err
		}
	}
	for _, issue := range report.Issues {
		if _, err = fmt.Fprintf(writer, "issue %s %s: %s\n", issue.ID, issue.Reason, issue.Message); err != nil {
			return err
		}
	}
	return nil
}

// conditionOutcomes renders ids with whether each held, in ID order, or nothing
// without conditions.
func conditionOutcomes(ids []string, held map[string]bool) string {
	if len(ids) == 0 {
		return ""
	}
	outcomes := make([]string, 0, len(ids))
	for _, id := range slices.Sorted(slices.Values(ids)) {
		outcomes = append(outcomes, fmt.Sprintf("%s:%t", id, held[id]))
	}
	return " conditions=" + strings.Join(outcomes, ",")
}
