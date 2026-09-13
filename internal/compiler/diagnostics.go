package compiler

import (
	"slices"

	"github.com/zcayou/k8s-authz/internal/model"
)

// addDiagnostic records issue for the use and document it concerns. Past
// maxAdvisories it keeps the entries with the least keys, so the retained
// selection doesn't depend on compile order. Keys start with the severity,
// so errors are kept before warnings.
func (b *builder) addDiagnostic(use string, origin model.DocumentKey, issue model.Issue) {
	key := string(issue.Severity) + model.Digest(struct {
		Use    string
		Origin model.DocumentKey
		Reason model.IssueReason
	}{use, origin, issue.Reason})
	if _, exists := b.diagnostics[key]; exists {
		return
	}
	if len(b.diagnostics) < maxAdvisories {
		b.diagnostics[key] = issue
		return
	}
	b.output.DiagnosticsTruncated = true
	greatest := ""
	for existing := range b.diagnostics {
		if existing > greatest {
			greatest = existing
		}
	}
	if key < greatest {
		delete(b.diagnostics, greatest)
		b.diagnostics[key] = issue
	}
}

func (b *builder) finalizeDiagnostics() {
	keys := make([]string, 0, len(b.diagnostics))
	for key := range b.diagnostics {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	b.output.Diagnostics = make([]model.Issue, 0, len(keys))
	for _, key := range keys {
		b.output.Diagnostics = append(b.output.Diagnostics, b.diagnostics[key])
	}
}
