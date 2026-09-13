package model

// MatcherKind discriminates a Matcher's two forms.
type MatcherKind string

const (
	MatcherSubjects     MatcherKind = "Subjects"
	MatcherRequirements MatcherKind = "Requirements"
)

const (
	KindUser             = "User"
	KindGroup            = "Group"
	KindServiceAccount   = "ServiceAccount"
	OperatorIn           = "In"
	OperatorNotIn        = "NotIn"
	OperatorExists       = "Exists"
	OperatorDoesNotExist = "DoesNotExist"
)

type Principal struct {
	User   string              `json:"user"`
	Groups []string            `json:"groups"`
	UID    string              `json:"uid"`
	Extra  map[string][]string `json:"extra"`
}

// Matcher is either a native subject union or a conjunction of requirements.
// The discriminator preserves the two forms' different empty-list meanings.
type Matcher struct {
	Kind         MatcherKind          `json:"kind"`
	Subjects     []PrincipalSubject   `json:"subjects,omitempty"`
	Requirements []SubjectRequirement `json:"requirements,omitempty"`
}
type PrincipalSubject struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}
type SubjectRequirement struct {
	Kind      string   `json:"kind"`
	Operator  string   `json:"operator"`
	Namespace string   `json:"namespace,omitempty"`
	Key       string   `json:"key,omitempty"`
	Values    []string `json:"values,omitempty"`
}

func AllPrincipals() Matcher {
	return Matcher{Kind: MatcherRequirements}
}
