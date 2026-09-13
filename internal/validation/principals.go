package validation

import (
	"errors"
	"slices"
	"strings"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
)

// principalSubject resolves a subject to the principal it matches.
// A ServiceAccount becomes its user name, so its namespace and name must not
// forge another.
func principalSubject(subject api.Subject) (model.PrincipalSubject, error) {
	if strings.ContainsRune(subject.Name, '\x00') {
		return model.PrincipalSubject{}, errors.New("subject name must not contain NUL")
	}
	if subject.Kind != model.KindServiceAccount {
		return model.PrincipalSubject{Kind: subject.Kind, Name: subject.Name}, nil
	}
	if err := validNamespace(subject.Namespace); err != nil {
		return model.PrincipalSubject{}, err
	}
	if err := validName(subject.Name); err != nil {
		return model.PrincipalSubject{}, err
	}
	return model.PrincipalSubject{Kind: model.KindUser, Name: "system:serviceaccount:" + subject.Namespace + ":" + subject.Name}, nil
}

// principal resolves exactly one of subjects or subjectMatch. It merges
// subjects that resolve to the same principal.
func principal(subjects []api.Subject, match *api.SubjectMatch) (model.Matcher, error) {
	if match != nil {
		return subjectMatch(match.Requirements)
	}
	result := model.Matcher{Kind: model.MatcherSubjects}
	for _, subject := range subjects {
		value, err := principalSubject(subject)
		if err != nil {
			return model.Matcher{}, err
		}
		result.Subjects = append(result.Subjects, value)
	}
	sortCanonical(result.Subjects)
	result.Subjects = slices.Compact(result.Subjects)
	return result, nil
}

func subjectMatch(requirements []api.SubjectRequirement) (model.Matcher, error) {
	result := model.AllPrincipals()
	for _, requirement := range requirements {
		value, err := subjectRequirement(requirement)
		if err != nil {
			return model.Matcher{}, err
		}
		result.Requirements = append(result.Requirements, value)
	}
	sortCanonical(result.Requirements)
	return result, nil
}

func subjectRequirement(r api.SubjectRequirement) (model.SubjectRequirement, error) {
	result := model.SubjectRequirement{Kind: r.Kind, Operator: r.Operator, Key: r.Key, Namespace: r.Namespace, Values: slices.Clone(r.Values)}
	if r.Kind == model.KindUser || r.Kind == model.KindGroup || r.Kind == model.KindServiceAccount {
		result.Values = slices.Clone(r.Names)
	}
	if strings.ContainsRune(r.Key, '\x00') || slices.ContainsFunc(result.Values, func(value string) bool { return strings.ContainsRune(value, '\x00') }) {
		return result, errors.New("subject requirement must not contain NUL")
	}
	if r.Kind == model.KindServiceAccount && (r.Operator == model.OperatorIn || r.Operator == model.OperatorNotIn) {
		for _, name := range result.Values {
			if err := validName(name); err != nil {
				return result, err
			}
		}
	}
	slices.Sort(result.Values)
	return result, nil
}

// sortCanonical orders values by the digest of their encoding.
func sortCanonical[T any](values []T) {
	type keyed struct {
		key   string
		value T
	}
	entries := make([]keyed, len(values))
	for index, value := range values {
		entries[index] = keyed{model.Digest(value), value}
	}
	slices.SortFunc(entries, func(a, b keyed) int { return strings.Compare(a.key, b.key) })
	for index, entry := range entries {
		values[index] = entry.value
	}
}
