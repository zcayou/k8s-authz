package model

type Decision struct {
	Result          Result     `json:"result"`
	Endpoint        string     `json:"endpoint"`
	Authority       string     `json:"authority,omitempty"`
	Revision        RevisionID `json:"revision"`
	Reason          string     `json:"reason"`
	Code            string     `json:"code"`
	EvaluationError string     `json:"evaluationError,omitempty"`
	ContributionIDs []string   `json:"contributionIDs,omitempty"`
	IssueIDs        []string   `json:"issueIDs,omitempty"`
}
