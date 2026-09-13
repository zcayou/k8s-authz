package model

// Effect is what a contribution does to the requests it covers.
type Effect string

const (
	EffectAllow Effect = "Allow"
	EffectDeny  Effect = "Deny"
)

// Result is an authorization decision's outcome: Allow, Deny or NoOpinion.
// Deny and NoOpinion are also the fallbacks an endpoint or authority answers
// with, the API's DecisionFallback values.
type Result string

type Contribution struct {
	ID           string        `json:"id"`
	Effect       Effect        `json:"effect"`
	PrincipalIDs []string      `json:"principalIDs"`
	ContextID    string        `json:"contextID"`
	Path         []DocumentKey `json:"path"`
	ConditionIDs []string      `json:"conditionIDs,omitempty"`
}

// ProgramIssue is an authoritative failure: an entry binding, the root
// PolicySet it targets or that entry's bound, or a prohibition couldn't
// be resolved for the principals it names.
type ProgramIssue struct {
	Issue
	PrincipalIDs []string `json:"principalIDs"`
}

// ExclusionProof records a removed region in a contextual policy use.
// It is diagnostic evidence and is never an authorization contribution.
type ExclusionProof struct {
	ID           string        `json:"id"`
	Endpoint     string        `json:"endpoint"`
	Authority    string        `json:"authority"`
	Effect       Effect        `json:"effect"`
	DiagramID    string        `json:"diagramID"`
	PrincipalIDs []string      `json:"principalIDs"`
	ContextID    string        `json:"contextID"`
	Path         []DocumentKey `json:"path"`
}

// AuthorityProgram is one authority's compiled diagrams. The composed Allow
// diagram decides alone; the independent diagrams are pushed only when
// it exceeded its limits and was omitted, and each covers a request only
// on its own.
type AuthorityProgram struct {
	SelectionErrorIDs             []string  `json:"selectionErrorIDs,omitempty"`
	Name                          string    `json:"name"`
	MatcherID                     string    `json:"matcherID"`
	Root                          Reference `json:"root"`
	Fallback                      Result    `json:"fallback"`
	ProhibitionDiagramID          string    `json:"prohibitionDiagramID"`
	IndependentAllowDiagramIDs    []string  `json:"independentAllowDiagramIDs,omitempty"`
	ComposedAllowDiagramID        string    `json:"composedAllowDiagramID,omitempty"`
	AuthoritativeFailureDiagramID string    `json:"authoritativeFailureDiagramID"`
}

// EndpointProgram is one endpoint's compiled policy and the Common Names
// of the callers it admits.
type EndpointProgram struct {
	Name                string             `json:"name"`
	WhenEvaluationFails Result             `json:"whenEvaluationFails"`
	Callers             []string           `json:"callers"`
	Authorities         []AuthorityProgram `json:"authorities"`
}

// PreparedRevision is a compiled program. It carries no deployment identity,
// so every service with the same endpoints and sources compiles the same
// program.
type PreparedRevision struct {
	Endpoints           map[string]EndpointProgram `json:"endpoints"`
	Predicates          map[string]Matcher         `json:"predicates"`
	Contributions       map[string]Contribution    `json:"contributions"`
	Diagrams            map[string]Diagram         `json:"diagrams"`
	Issues              map[string]ProgramIssue    `json:"issues"`
	Exclusions          map[string]ExclusionProof  `json:"exclusions,omitempty"`
	ExclusionsTruncated bool                       `json:"exclusionsTruncated,omitempty"`
	Conditions          map[string]Condition       `json:"conditions,omitempty"`
}

// ContentRevision is the state document pushed to a service's engines: its
// program bound to the service UID, the evaluator that runs it and the digest
// of the conditions module it calls, addressed by the digest of all four.
type ContentRevision struct {
	PreparedRevision
	ServiceUID       ServiceUID `json:"serviceUID"`
	EvaluatorID      string     `json:"evaluatorID"`
	ConditionsDigest string     `json:"conditionsDigest"`
	Revision         RevisionID `json:"revision,omitempty"`
}
