package model

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
)

type SourceKey struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// SourceInstance identifies the documents one PolicySource serves:
// the PolicySource incarnation and the normalized API server URL it reads from.
// It never contains credential material, so rotating a credential keeps
// document identity.
type SourceInstance struct {
	Key    SourceKey `json:"key"`
	UID    string    `json:"uid"`
	Origin string    `json:"origin"`
}
type DocumentKey struct {
	Source    SourceInstance `json:"source"`
	Group     string         `json:"group"`
	Kind      string         `json:"kind"`
	Namespace string         `json:"namespace"`
	Name      string         `json:"name"`
}
type Reference struct {
	Source    SourceKey `json:"source"`
	Group     string    `json:"group"`
	Kind      string    `json:"kind"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
}

func (k DocumentKey) Reference() Reference {
	return Reference{Source: k.Source.Key, Group: k.Group, Kind: k.Kind, Namespace: k.Namespace, Name: k.Name}
}
func (k DocumentKey) String() string {
	return fmt.Sprintf("%s/%s@%s:%s/%s/%s/%s", k.Source.Key.Namespace, k.Source.Key.Name, k.Source.UID, k.Group, k.Kind, k.Namespace, k.Name)
}
func (r Reference) String() string {
	return fmt.Sprintf("%s/%s:%s/%s/%s/%s", r.Source.Namespace, r.Source.Name, r.Group, r.Kind, r.Namespace, r.Name)
}

// IssueReason classifies an issue. Validation and the compiler emit these
// reasons, and consumers compare against the constants.
type IssueReason string

const (
	// ReasonInvalid means a document failed strict decoding or validation.
	ReasonInvalid IssueReason = "Invalid"
	// ReasonKindMismatch means a reference names a document of a kind its
	// field can't refer to.
	ReasonKindMismatch IssueReason = "KindMismatch"
	// ReasonInternalError means the compiler failed in a way no document
	// explains.
	ReasonInternalError              IssueReason = "InternalError"
	ReasonResourceLimitExceeded      IssueReason = "ResourceLimitExceeded"
	ReasonSourceUnavailable          IssueReason = "SourceUnavailable"
	ReasonSourceNotAllowed           IssueReason = "SourceNotAllowed"
	ReasonInvalidDocument            IssueReason = "InvalidDocument"
	ReasonMissingReference           IssueReason = "MissingReference"
	ReasonDepthExceeded              IssueReason = "DepthExceeded"
	ReasonInvalidSourceRestriction   IssueReason = "InvalidSourceRestriction"
	ReasonCycle                      IssueReason = "Cycle"
	ReasonDenyOutsideRoot            IssueReason = "DenyOutsideRoot"
	ReasonNamespaceScopeConservative IssueReason = "NamespaceScopeConservative"
	ReasonAllNamespacesNotGranted    IssueReason = "AllNamespacesNotGranted"
	// ReasonRegoNotAllowed means a condition's source, or a source on its path,
	// doesn't allow Rego conditions.
	ReasonRegoNotAllowed IssueReason = "RegoNotAllowed"
	// ReasonBuiltinNotAllowed means a condition calls a builtin its path
	// doesn't allow.
	ReasonBuiltinNotAllowed IssueReason = "BuiltinNotAllowed"
	// ReasonConditionalProhibition means a prohibition would carry a condition.
	ReasonConditionalProhibition IssueReason = "ConditionalProhibition"
	// ReasonGrantsNotComposed means an authority's composed Allow diagram
	// exceeded its limits, so its root bindings' grants cover a request only
	// one binding at a time.
	ReasonGrantsNotComposed IssueReason = "GrantsNotComposed"
	// ReasonUniversalEnvelope means a Policy's condition decides every request
	// inside its bound.
	ReasonUniversalEnvelope IssueReason = "UniversalEnvelope"
	// ReasonNamespaceLabelsNotCollected means a selection's namespaceSelector
	// needs namespace labels its source doesn't collect.
	ReasonNamespaceLabelsNotCollected IssueReason = "NamespaceLabelsNotCollected"
)

type Issue struct {
	Severity  api.IssueSeverity `json:"severity"`
	Reason    IssueReason       `json:"reason"`
	Message   string            `json:"message"`
	Scope     api.IssueScope    `json:"scope"`
	Document  *DocumentKey      `json:"document,omitempty"`
	Endpoint  string            `json:"endpoint,omitempty"`
	Authority string            `json:"authority,omitempty"`
	ContextID string            `json:"contextID,omitempty"`
	Path      []DocumentKey     `json:"path,omitempty"`
}

// DocumentState is one acquired document. A valid document carries its
// decoded Document; an invalid one carries only the issues that reject it.
type DocumentState struct {
	Key DocumentKey `json:"key"`
	UID string      `json:"uid"`
	// Digest covers what the document contributes to a compilation it's referenced
	// in: the normalized document and its issues.
	Digest   string    `json:"digest"`
	Document *Document `json:"document,omitempty"`
	Issues   []Issue   `json:"issues,omitempty"`
	// Labels are a PolicySet's labels, valid or not, which selections match.
	// Other kinds carry none. Digest doesn't cover them: they decide only
	// what a selection matches.
	Labels map[string]string `json:"labels,omitempty"`
	// Object is the canonical JSON of the acquired object, without server-managed
	// field history. It's what the persistent cache stores.
	Object []byte `json:"-"`
}

// Document is a strictly decoded tagged union. Only the payload for Key.Kind
// is populated.
type Document struct {
	Key     DocumentKey `json:"key"`
	Policy  *Policy     `json:"policy,omitempty"`
	Binding *Binding    `json:"binding,omitempty"`
	Set     *PolicySet  `json:"set,omitempty"`
}
type Cube map[string]Region
type Policy struct {
	Include   []Cube     `json:"include"`
	Exclude   []Cube     `json:"exclude"`
	Imports   []Import   `json:"imports"`
	Condition *Condition `json:"condition,omitempty"`
}

// Condition is a checked Rego condition. ID is the digest of Rego, and Builtins
// are the builtins it calls.
type Condition struct {
	ID       string     `json:"id"`
	Rego     string     `json:"rego"`
	Builtins BuiltinSet `json:"builtins,omitempty"`
}
type Import struct {
	Reference  Reference `json:"reference"`
	Namespaces []string  `json:"namespaces,omitempty"`
}

// Binding attaches its principals to Policy, or, when Selection is set
// and Policy is zero, to each PolicySet Selection matches.
type Binding struct {
	Policy    Reference   `json:"policy"`
	Selection *Selection  `json:"selection,omitempty"`
	Principal Matcher     `json:"principal"`
	Namespace string      `json:"namespace,omitempty"`
	Bound     *Reference  `json:"bound,omitempty"`
	Sources   []SourceKey `json:"sources,omitempty"`
	MaxDepth  *int        `json:"maxDepth,omitempty"`
}

// Selection selects the PolicySets of Source whose own labels match Sets
// and whose namespace's labels match Namespaces.
type Selection struct {
	Source     SourceKey     `json:"source"`
	Namespaces LabelSelector `json:"namespaces,omitempty"`
	Sets       LabelSelector `json:"sets,omitempty"`
}

// MatchesSet reports whether reference is a PolicySet whose labels match
// the selection's selector, whatever its namespace's labels.
func (s Selection) MatchesSet(reference Reference, labels map[string]string) bool {
	return reference.Kind == KindPolicySet && reference.Group == DocumentKinds[KindPolicySet].Resource.Group && s.Sets.Matches(labels)
}

// LabelSelector is a normalized label selector: the requirements, with each
// matchLabels entry as an In requirement, sorted with their values sorted.
// An empty selector matches every label set.
type LabelSelector []metav1.LabelSelectorRequirement

// Matches reports whether labels satisfy every requirement, as a Kubernetes
// label selector does.
func (s LabelSelector) Matches(labels map[string]string) bool {
	for _, requirement := range s {
		value, present := labels[requirement.Key]
		var satisfied bool
		switch requirement.Operator {
		case metav1.LabelSelectorOpIn:
			satisfied = present && slices.Contains(requirement.Values, value)
		case metav1.LabelSelectorOpNotIn:
			satisfied = !present || !slices.Contains(requirement.Values, value)
		case metav1.LabelSelectorOpExists:
			satisfied = present
		case metav1.LabelSelectorOpDoesNotExist:
			satisfied = !present
		}
		if !satisfied {
			return false
		}
	}
	return true
}

type PolicySet struct {
	Bindings     []Reference `json:"bindings"`
	Prohibitions []Reference `json:"prohibitions"`
}

// SourceObservation is one source's view. A complete observation carries every
// collected document; an incomplete one carries the Failure that keeps it from
// completing. Observations are immutable once emitted: consumers share their
// maps, slices and documents and never modify them.
type SourceObservation struct {
	Instance  SourceInstance
	Documents map[Reference]DocumentState
	Failure   Failure
	Complete  bool
	// AllowedBuiltins are the builtins the source's conditions may call. Nil
	// means the source doesn't allow Rego conditions.
	AllowedBuiltins *BuiltinSet
	// CollectsNamespaceLabels reports whether the source reads namespace
	// labels. When it does, a complete observation's NamespaceLabels holds
	// the labels of each collected namespace that exists in the source.
	CollectsNamespaceLabels bool
	NamespaceLabels         map[string]map[string]string
}

// Failure is why a source has no complete observation. Reason is a Synchronized
// condition reason, or the contribution Inert.
type Failure struct {
	Reason  string
	Message string
}

// Digest is the SHA-256 of value's JSON encoding. encoding/json writes map keys
// sorted and struct fields in declaration order, so the encoding
// is deterministic. Callers normalize set-valued lists. value must encode,
// as the model's types and plain data always do; Digest panics otherwise.
func Digest(value any) string {
	hash := sha256.New()
	if err := json.NewEncoder(hash).Encode(value); err != nil {
		panic(fmt.Sprintf("digest %T: %v", value, err))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func SortReferences(refs []Reference) {
	slices.SortFunc(refs, func(a, b Reference) int {
		return cmp.Or(
			strings.Compare(a.Source.Namespace, b.Source.Namespace),
			strings.Compare(a.Source.Name, b.Source.Name),
			strings.Compare(a.Group, b.Group),
			strings.Compare(a.Kind, b.Kind),
			strings.Compare(a.Namespace, b.Namespace),
			strings.Compare(a.Name, b.Name),
		)
	})
}
