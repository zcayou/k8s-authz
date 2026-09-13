package compiler

import (
	"fmt"
	"slices"
	"strings"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
)

type Compilation struct {
	Prepared model.PreparedRevision
	// References are the documents the compilation read.
	References           map[model.Reference]struct{}
	Diagnostics          []model.Issue
	DiagnosticsTruncated bool
}

type useContext struct {
	endpoint      string
	authority     string
	root          bool
	sources       map[model.SourceKey]bool
	path          []model.DocumentKey
	aliases       []string
	remaining     int
	principals    []string
	bound         model.NodeID
	advisoryBound model.NodeID
	// conditions are the IDs of the Rego conditions the use's Policies carry.
	conditions []string
	// builtins are the builtins the path's bindings and PolicySets allow,
	// nil while none has restricted them.
	builtins *model.BuiltinSet
	// forbiddenBy is the first source on the path that doesn't allow Rego
	// conditions, nil while there is none.
	forbiddenBy *model.SourceKey
}

func (u useContext) identity() string {
	sources := make([]model.SourceKey, 0, len(u.sources))
	for key := range u.sources {
		sources = append(sources, key)
	}
	slices.SortFunc(sources, func(a, b model.SourceKey) int { return strings.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name) })
	return model.Digest(struct {
		Endpoint, Authority string
		Path                []model.DocumentKey
		Principals          []string
		Sources             []model.SourceKey
		Remaining           int
	}{u.endpoint, u.authority, u.path, u.principals, sources, u.remaining})
}
func (u useContext) derive() useContext {
	u.path = slices.Clone(u.path)
	u.aliases = slices.Clone(u.aliases)
	u.principals = slices.Clone(u.principals)
	u.conditions = slices.Clone(u.conditions)
	return u
}
func (u useContext) issue(reason model.IssueReason, message string) model.ProgramIssue {
	return model.ProgramIssue{Issue: model.Issue{Severity: api.IssueSeverityError, Reason: reason, Message: message, Scope: api.IssueScopeUse, Endpoint: u.endpoint, Authority: u.authority, ContextID: u.identity(), Path: slices.Clone(u.path)}, PrincipalIDs: slices.Clone(u.principals)}
}
func alias(key model.DocumentKey) string {
	return fmt.Sprintf("%s:%s/%s/%s/%s", key.Source.Origin, key.Group, key.Kind, key.Namespace, key.Name)
}
