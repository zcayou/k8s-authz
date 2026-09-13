package cli

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/validate/content"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation/field"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/validation"
)

const (
	maxInputBytes            = 32 << 20
	authorizationServiceKind = "AuthorizationService"
	policySourceKind         = "PolicySource"
)

// The reasons validation reports besides those of the operator's issues.
const (
	// reasonInvalidSyntax means a document isn't well-formed YAML or JSON.
	reasonInvalidSyntax model.IssueReason = "InvalidSyntax"
	// reasonUnsupportedDocument means a document's kind isn't one the command
	// validates.
	reasonUnsupportedDocument model.IssueReason = "UnsupportedDocument"
	// reasonSourceRequired means a policy document has no --source to belong to.
	reasonSourceRequired model.IssueReason = "SourceRequired"
	// reasonDuplicateDocument means a source holds two documents with one
	// identity.
	reasonDuplicateDocument model.IssueReason = "DuplicateDocument"
	// reasonInvalidGraphInput means the service file doesn't hold exactly one
	// AuthorizationService.
	reasonInvalidGraphInput model.IssueReason = "InvalidGraphInput"
	// reasonCompilationFailed means the service's policy couldn't be compiled.
	reasonCompilationFailed model.IssueReason = "CompilationFailed"
	// reasonDiagnosticsTruncated means the compiler kept only part of its
	// diagnostics.
	reasonDiagnosticsTruncated model.IssueReason = "DiagnosticsTruncated"
)

// documentIdentity identifies the document to which a diagnostic applies.
type documentIdentity struct {
	Source    *model.SourceKey `json:"source,omitempty"`
	APIGroup  string           `json:"apiGroup,omitempty"`
	Kind      string           `json:"kind,omitempty"`
	Namespace string           `json:"namespace,omitempty"`
	Name      string           `json:"name,omitempty"`
}

// diagnostic is one attributed validation result.
type diagnostic struct {
	File      string             `json:"file"`
	Document  int                `json:"document"`
	Source    *model.SourceKey   `json:"source,omitempty"`
	Identity  documentIdentity   `json:"identity,omitzero"`
	FieldPath string             `json:"fieldPath,omitempty"`
	Severity  api.IssueSeverity  `json:"severity"`
	Reason    model.IssueReason  `json:"reason"`
	Message   string             `json:"message"`
	Endpoint  string             `json:"endpoint,omitempty"`
	Authority string             `json:"authority,omitempty"`
	ContextID string             `json:"contextID,omitempty"`
	Path      []documentIdentity `json:"path,omitempty"`
}

// validationReport is the result of a document or graph validation.
type validationReport struct {
	Valid       bool         `json:"valid"`
	Documents   int          `json:"documents"`
	Diagnostics []diagnostic `json:"diagnostics"`
}

func newValidateCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "validate",
		Short: "Strictly validate policy documents without network access",
		Long: `Validate strictly decodes documents, applies the API server's metadata rules
and the operator's semantic rules, without network access. The CRD schemas and
their CEL rules need an API server: kubectl apply --dry-run=server checks them.`,
	}
	command.AddCommand(newValidateDocumentsCommand())
	command.AddCommand(newValidateGraphCommand())
	return command
}

type documentsOptions struct {
	source string
	output string
}

func newValidateDocumentsCommand() *cobra.Command {
	options := &documentsOptions{}
	command := &cobra.Command{
		Use:   "documents FILE...",
		Short: "Validate policy, RBAC, PolicySource and AuthorizationService documents",
		Long: `Validate documents validates each document in the files, or in standard input
for -. Policy and RBAC documents belong to the PolicySource --source names.`,
		Args: cobra.MinimumNArgs(1),
		RunE: options.run,
	}
	command.Flags().StringVar(&options.source, "source", "", "NAMESPACE/NAME of the PolicySource every policy and RBAC document belongs to")
	registerOutputFlag(command, &options.output)
	return command
}

func (o *documentsOptions) run(command *cobra.Command, files []string) error {
	if err := checkOutput(o.output); err != nil {
		return err
	}
	if countValue(files, "-") > 1 {
		return errors.New("standard input may be specified only once")
	}
	var observation *model.SourceObservation
	if o.source != "" {
		parsed, err := parseSourceKey(o.source)
		if err != nil {
			return fmt.Errorf("invalid --source: %w", err)
		}
		observation = &model.SourceObservation{Instance: model.SourceInstance{Key: parsed}, Documents: map[model.Reference]model.DocumentState{}}
	}
	report := validationReport{Diagnostics: []diagnostic{}}
	for _, file := range files {
		data, err := readInput(command.InOrStdin(), file, maxInputBytes)
		if err != nil {
			return err
		}
		report.Documents += yamlDocuments(data, func(number int, document []byte, err error) {
			if err != nil {
				report.Diagnostics = append(report.Diagnostics, errorDiagnostic(file, number, nil, documentIdentity{}, reasonInvalidSyntax, err))
				return
			}
			report.Diagnostics = append(report.Diagnostics, validateDocument(file, number, document, observation)...)
		})
	}
	return writeValidationReport(command.OutOrStdout(), o.output, report)
}

// readInput reads the file name, or standard input for "-", up to limit bytes.
func readInput(stdin io.Reader, name string, limit int64) ([]byte, error) {
	if name == "-" {
		return readLimited(stdin, name, limit)
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", name, err)
	}
	data, readErr := readLimited(file, name, limit)
	if closeErr := file.Close(); readErr == nil && closeErr != nil {
		return nil, fmt.Errorf("close %q: %w", name, closeErr)
	}
	return data, readErr
}

// readLimited reads reader, the input name names, up to limit bytes.
func readLimited(reader io.Reader, name string, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("read %q: input exceeds %d bytes", name, limit)
	}
	return data, nil
}

// yamlDocuments calls visit with the JSON of each nonempty document in data,
// numbered from 1, or with the syntax error that ends the stream.
func yamlDocuments(data []byte, visit func(number int, document []byte, err error)) int {
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	number := 0
	for {
		raw, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return number
		}
		if err != nil {
			visit(number+1, nil, err)
			return number
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		number++
		document, err := yaml.YAMLToJSONStrict(raw)
		visit(number, document, err)
	}
}

// validateDocument validates one document. Policy and RBAC documents join
// observation, which is nil without --source.
func validateDocument(file string, number int, data []byte, observation *model.SourceObservation) []diagnostic {
	object := &unstructured.Unstructured{}
	if err := object.UnmarshalJSON(data); err != nil {
		return []diagnostic{errorDiagnostic(file, number, sourceKey(observation), documentIdentity{}, model.ReasonInvalid, err)}
	}
	identity := identityFrom(object)
	switch object.GroupVersionKind() {
	case api.GroupVersion.WithKind(policySourceKind):
		errs := validateMetadata(object, true)
		errs = append(errs, validation.DecodeStrict(object, &api.PolicySource{})...)
		return fieldDiagnostics(file, number, nil, identity, errs)
	case api.GroupVersion.WithKind(authorizationServiceKind):
		_, _, errs := decodeService(object)
		return fieldDiagnostics(file, number, nil, identity, errs)
	}
	return addSourceDocument(observation, file, number, object)
}

// decodeService strictly decodes an offline AuthorizationService, applying
// the API server's metadata rules, and returns it with its configuration.
// It returns no service when it reports an error.
func decodeService(object *unstructured.Unstructured) (*api.AuthorizationService, model.ServiceConfig, field.ErrorList) {
	errs := validateMetadata(object, true)
	var service api.AuthorizationService
	if errs = append(errs, validation.DecodeStrict(object, &service)...); len(errs) != 0 {
		return nil, model.ServiceConfig{}, errs
	}
	config, errs := validation.DecodeService(&service)
	if len(errs) != 0 {
		return nil, model.ServiceConfig{}, errs
	}
	return &service, config, nil
}

// validateMetadata applies the API server's metadata rules to object. RBAC
// names are path segments; custom resource names are DNS subdomains.
func validateMetadata(object *unstructured.Unstructured, namespaced bool) field.ErrorList {
	name := apivalidation.NameIsDNSSubdomain
	if object.GroupVersionKind().Group == rbacv1.GroupName {
		name = rbacName
	}
	return apivalidation.ValidateObjectMetaAccessor(object, namespaced, name, field.NewPath("metadata"))
}

// rbacName validates an RBAC name, or a generateName prefix, as the RBAC API
// does: as a path segment.
func rbacName(name string, prefix bool) []string {
	if prefix {
		return content.IsPathSegmentPrefix(name)
	}
	return content.IsPathSegmentName(name)
}

// policyDocumentKind returns the kind of a policy or RBAC document.
func policyDocumentKind(object *unstructured.Unstructured) (model.DocumentKind, bool) {
	gvk := object.GroupVersionKind()
	documentKind, found := model.DocumentKinds[gvk.Kind]
	return documentKind, found && documentKind.Resource.GroupVersion() == gvk.GroupVersion()
}

func identityFrom(object *unstructured.Unstructured) documentIdentity {
	gvk := object.GroupVersionKind()
	return documentIdentity{APIGroup: gvk.Group, Kind: gvk.Kind, Namespace: object.GetNamespace(), Name: object.GetName()}
}

// fieldMessage is the diagnostic's message, prefixed with its field path.
func (d diagnostic) fieldMessage() string {
	if d.FieldPath == "" {
		return d.Message
	}
	return d.FieldPath + ": " + d.Message
}

func errorDiagnostic(file string, document int, source *model.SourceKey, identity documentIdentity, reason model.IssueReason, err error) diagnostic {
	return diagnostic{File: file, Document: document, Source: source, Identity: identity, Severity: api.IssueSeverityError, Reason: reason, Message: err.Error()}
}

// fieldDiagnostics reports each error of errs with its field path.
func fieldDiagnostics(file string, document int, source *model.SourceKey, identity documentIdentity, errs field.ErrorList) []diagnostic {
	diagnostics := make([]diagnostic, 0, len(errs))
	for _, err := range errs {
		diagnostics = append(diagnostics, diagnostic{File: file, Document: document, Source: source, Identity: identity, FieldPath: err.Field, Severity: api.IssueSeverityError, Reason: model.ReasonInvalid, Message: err.ErrorBody()})
	}
	return diagnostics
}

func unsupportedDiagnostic(file string, document int, source *model.SourceKey, identity documentIdentity, object *unstructured.Unstructured) diagnostic {
	return errorDiagnostic(file, document, source, identity, reasonUnsupportedDocument, fmt.Errorf("unsupported apiVersion %q and kind %q", object.GetAPIVersion(), object.GetKind()))
}

func duplicateDiagnostic(file string, document int, source *model.SourceKey, identity documentIdentity) diagnostic {
	return errorDiagnostic(file, document, source, identity, reasonDuplicateDocument, errors.New("duplicate source-qualified document identity"))
}

// issueDiagnostics reports the issues of the document numbered document.
func issueDiagnostics(file string, document int, issues []model.Issue) []diagnostic {
	diagnostics := make([]diagnostic, 0, len(issues))
	for _, issue := range issues {
		result := diagnosticFromIssue(file, issue)
		result.Document = document
		diagnostics = append(diagnostics, result)
	}
	return diagnostics
}

func diagnosticFromIssue(file string, issue model.Issue) diagnostic {
	result := diagnostic{File: file, Document: 1, Severity: issue.Severity, Reason: issue.Reason, Message: issue.Message, Endpoint: issue.Endpoint, Authority: issue.Authority, ContextID: issue.ContextID}
	if issue.Document != nil {
		result.Source = new(issue.Document.Source.Key)
		result.Identity = identityFromDocumentKey(*issue.Document)
	}
	for _, key := range issue.Path {
		result.Path = append(result.Path, identityFromDocumentKey(key))
	}
	return result
}

func identityFromDocumentKey(key model.DocumentKey) documentIdentity {
	return documentIdentity{Source: new(key.Source.Key), APIGroup: key.Group, Kind: key.Kind, Namespace: key.Namespace, Name: key.Name}
}

func compareDiagnostics(left, right diagnostic) int {
	return cmp.Or(
		strings.Compare(left.File, right.File),
		cmp.Compare(left.Document, right.Document),
		cmp.Compare(left.Reason, right.Reason),
		strings.Compare(left.Message, right.Message),
		compareSources(left.Source, right.Source),
		compareDocumentIdentities(left.Identity, right.Identity),
		strings.Compare(left.FieldPath, right.FieldPath),
		cmp.Compare(left.Severity, right.Severity),
		strings.Compare(left.Endpoint, right.Endpoint),
		strings.Compare(left.Authority, right.Authority),
		strings.Compare(left.ContextID, right.ContextID),
		slices.CompareFunc(left.Path, right.Path, compareDocumentIdentities),
	)
}

func compareDocumentIdentities(left, right documentIdentity) int {
	return cmp.Or(
		compareSources(left.Source, right.Source),
		strings.Compare(left.APIGroup, right.APIGroup),
		strings.Compare(left.Kind, right.Kind),
		strings.Compare(left.Namespace, right.Namespace),
		strings.Compare(left.Name, right.Name),
	)
}

// compareSources orders an absent source before any present one.
func compareSources(left, right *model.SourceKey) int {
	switch {
	case left == nil && right == nil:
		return 0
	case left == nil:
		return -1
	case right == nil:
		return 1
	}
	return cmp.Or(strings.Compare(left.Namespace, right.Namespace), strings.Compare(left.Name, right.Name))
}

// writeValidationReport sorts report's diagnostics, writes it, and returns
// errInvalidReport when it holds an error.
func writeValidationReport(writer io.Writer, output string, report validationReport) error {
	slices.SortFunc(report.Diagnostics, compareDiagnostics)
	report.Diagnostics = slices.CompactFunc(report.Diagnostics, func(a, b diagnostic) bool { return compareDiagnostics(a, b) == 0 })
	report.Valid = !slices.ContainsFunc(report.Diagnostics, func(diagnostic diagnostic) bool { return diagnostic.Severity == api.IssueSeverityError })
	if err := encodeValidationReport(writer, output, report); err != nil {
		return fmt.Errorf("write validation report: %w", err)
	}
	if !report.Valid {
		return errInvalidReport
	}
	return nil
}

func encodeValidationReport(writer io.Writer, output string, report validationReport) error {
	if output == formatJSON {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(writer, "%s\n", encoded)
		return err
	}
	result := "valid"
	if !report.Valid {
		result = "invalid"
	}
	if _, err := fmt.Fprintf(writer, "%s: %d document(s)\n", result, report.Documents); err != nil {
		return err
	}
	for _, item := range report.Diagnostics {
		if _, err := fmt.Fprintf(writer, "%s:%d: %s %s: %s\n", item.File, item.Document, item.Severity, item.Reason, item.fieldMessage()); err != nil {
			return err
		}
	}
	return nil
}

// parseSourceKey parses a PolicySource's NAMESPACE/NAME.
func parseSourceKey(value string) (model.SourceKey, error) {
	namespace, name, found := strings.Cut(value, "/")
	if !found || namespace == "" || name == "" || strings.Contains(name, "/") {
		return model.SourceKey{}, errors.New("expected NAMESPACE/NAME")
	}
	return model.SourceKey{Namespace: namespace, Name: name}, nil
}

func countValue(values []string, expected string) int {
	count := 0
	for _, value := range values {
		if value == expected {
			count++
		}
	}
	return count
}
