package controller

import (
	"context"
	"slices"
	"strings"
	"unicode/utf8"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	apiac "github.com/zcayou/k8s-authz/api/v1alpha1/applyconfiguration/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
)

// applyStatus server-side applies a complete status, which the operator owns
// alone. The apply carries no resourceVersion, so a status computed from
// a cached object that predates the operator's own last status write replaces
// that write instead of conflicting with it.
func applyStatus(ctx context.Context, writer client.StatusClient, configuration runtime.ApplyConfiguration) error {
	return writer.Status().Apply(ctx, configuration, client.ForceOwnership)
}

// statusCondition returns conditionType's configuration. Its transition
// time is the existing condition's while the status is unchanged, and now
// otherwise.
func statusCondition(existing []metav1.Condition, generation int64, conditionType string, status metav1.ConditionStatus, reason, message string) *metav1ac.ConditionApplyConfiguration {
	transition := metav1.Now()
	if previous := apimeta.FindStatusCondition(existing, conditionType); previous != nil && previous.Status == status {
		transition = previous.LastTransitionTime
	}
	return metav1ac.Condition().
		WithType(conditionType).
		WithStatus(status).
		WithObservedGeneration(generation).
		WithLastTransitionTime(transition).
		WithReason(reason).
		WithMessage(boundedMessage(message))
}

const (
	maximumStatusIssues      = 128
	maximumIssueMessageBytes = 1024
)

// statusIssues converts issues to their bounded, deterministically ordered
// status form, and reports whether any were dropped. Errors sort before
// warnings, so truncation drops warnings first.
func statusIssues(issues []model.Issue) ([]*apiac.IssueApplyConfiguration, bool) {
	slices.SortFunc(issues, func(a, b model.Issue) int {
		left := strings.Join([]string{string(a.Severity), string(a.Scope), string(a.Reason), issueDocumentKey(a), a.Message}, "\x00")
		right := strings.Join([]string{string(b.Severity), string(b.Scope), string(b.Reason), issueDocumentKey(b), b.Message}, "\x00")
		return strings.Compare(left, right)
	})
	truncated := len(issues) > maximumStatusIssues
	issues = issues[:min(len(issues), maximumStatusIssues)]
	result := make([]*apiac.IssueApplyConfiguration, 0, len(issues))
	for _, issue := range issues {
		converted := apiac.Issue().
			WithSeverity(issue.Severity).
			WithReason(string(issue.Reason)).
			WithMessage(boundedMessage(issue.Message)).
			WithScope(issue.Scope)
		if issue.Endpoint != "" {
			converted.WithEndpoint(issue.Endpoint)
		}
		if issue.Authority != "" {
			converted.WithAuthority(issue.Authority)
		}
		if issue.ContextID != "" {
			converted.WithContextID(issue.ContextID)
		}
		if issue.Document != nil {
			converted.
				WithSourceRef(apiac.SourceRef().WithNamespace(issue.Document.Source.Key.Namespace).WithName(issue.Document.Source.Key.Name)).
				WithDocumentRef(qualifiedDocument(*issue.Document))
		}
		for _, document := range issue.Path {
			converted.WithPath(qualifiedDocument(document))
		}
		result = append(result, converted)
	}
	return result, truncated
}

func qualifiedDocument(document model.DocumentKey) *apiac.QualifiedDocumentRefApplyConfiguration {
	ref := apiac.QualifiedDocumentRef().WithGroup(document.Group).WithKind(document.Kind).WithName(document.Name)
	if document.Namespace != "" {
		ref.WithNamespace(document.Namespace)
	}
	return ref
}

func boundedMessage(message string) string {
	if len(message) <= maximumIssueMessageBytes {
		return message
	}
	message = message[:maximumIssueMessageBytes]
	for !utf8.ValidString(message) {
		message = message[:len(message)-1]
	}
	return message
}

func issueDocumentKey(issue model.Issue) string {
	if issue.Document == nil {
		return ""
	}
	return issue.Document.String()
}
