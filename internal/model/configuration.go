package model

type ServiceUID string
type RevisionID string

// Identity identifies one AuthorizationService incarnation.
type Identity struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}
type AuthorityConfig struct {
	Binding  Reference `json:"binding"`
	Fallback Result    `json:"fallback"`
}

// ServiceConfig is what the compiler reads of one AuthorizationService.
// BuiltinCeiling caps the builtins every use's conditions may call; nil
// imposes no cap.
type ServiceConfig struct {
	Endpoints      []EndpointConfig `json:"endpoints"`
	BuiltinCeiling *BuiltinSet      `json:"builtinCeiling,omitempty"`
}

// EndpointConfig is what the compiler reads of one endpoint. Its callers
// are the sorted, distinct Common Names the endpoint admits.
type EndpointConfig struct {
	Name                string            `json:"name"`
	Callers             []string          `json:"callers"`
	Sources             []SourceKey       `json:"sources"`
	Authorities         []AuthorityConfig `json:"authorities"`
	WhenEvaluationFails Result            `json:"whenEvaluationFails"`
}
