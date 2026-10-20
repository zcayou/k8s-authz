package compiler

import (
	"errors"
	"fmt"

	"github.com/zcayou/k8s-authz/internal/model"
)

// Selected is a selection's outcome against a set of sources: the instance
// of the source it read, and the PolicySets it matched in reference order,
// or the reason it failed.
type Selected struct {
	// Instance is zero when the source isn't registered.
	Instance model.SourceInstance `json:"instance"`
	Matches  []model.Reference    `json:"matches,omitempty"`
	Reason   model.IssueReason    `json:"reason,omitempty"`
	Message  string               `json:"message,omitempty"`
}

// err is why the selection failed, nil when it didn't.
func (s Selected) err() error {
	if s.Reason == "" {
		return nil
	}
	if s.Reason == model.ReasonResourceLimitExceeded {
		return fmt.Errorf("%s: %w", s.Message, model.ErrLimit)
	}
	return errorf(s.Reason, nil, "%s", s.Message)
}

// Select evaluates selection against sources. It fails when the selected source
// isn't registered or has no complete view, when its namespace selector isn't
// empty and the source doesn't collect namespace labels, and when more than
// limit PolicySets match. A PolicySet matches when its labels match
// the selection's, and, unless the namespace selector is empty, its namespace's
// labels are collected and match too. Matching nothing is success.
// The compiler, which also checks that the use may read the source, the program
// cache and the CLI all evaluate selections with it.
func Select(selection model.Selection, sources map[model.SourceKey]model.SourceObservation, limit int) Selected {
	source, err := available(sources, selection.Source)
	result := Selected{Instance: source.Instance}
	if err == nil && len(selection.Namespaces) > 0 && !source.CollectsNamespaceLabels {
		err = errorf(model.ReasonNamespaceLabelsNotCollected, nil, "source %s/%s doesn't collect namespace labels, which a non-empty namespaceSelector needs", selection.Source.Namespace, selection.Source.Name)
	}
	if failure, ok := errors.AsType[*compileError](err); ok {
		result.Reason, result.Message = failure.reason, failure.message
		return result
	}
	for reference, state := range source.Documents {
		if !selection.MatchesSet(reference, state.Labels) {
			continue
		}
		if len(selection.Namespaces) > 0 {
			labels, collected := source.NamespaceLabels[reference.Namespace]
			if !collected || !selection.Namespaces.Matches(labels) {
				continue
			}
		}
		result.Matches = append(result.Matches, reference)
	}
	if count := len(result.Matches); count > limit {
		return Selected{Instance: source.Instance, Reason: model.ReasonResourceLimitExceeded, Message: fmt.Sprintf("selection matches %d PolicySets, more than %d", count, limit)}
	}
	model.SortReferences(result.Matches)
	return result
}

// available returns the source key names when it holds a complete view,
// and otherwise why it's unavailable.
func available(sources map[model.SourceKey]model.SourceObservation, key model.SourceKey) (model.SourceObservation, error) {
	source, found := sources[key]
	if !found {
		return source, errorf(model.ReasonSourceUnavailable, nil, "source %s/%s isn't a registered PolicySource", key.Namespace, key.Name)
	}
	if !source.Complete {
		return source, errorf(model.ReasonSourceUnavailable, nil, "source %s/%s is unavailable (%s)", key.Namespace, key.Name, source.Failure.Reason)
	}
	return source, nil
}
