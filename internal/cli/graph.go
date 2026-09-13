package cli

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/validation"
)

type graphOptions struct {
	sources     []string
	regoSources []string
	output      string
}

func newValidateGraphCommand() *cobra.Command {
	options := &graphOptions{}
	command := &cobra.Command{
		Use:   "graph SERVICE_FILE --source NAMESPACE/NAME=FILE...",
		Short: "Compile an AuthorizationService against offline sources",
		Long: `Validate graph compiles the endpoints of the AuthorizationService in SERVICE_FILE
as the operator does, against sources that hold exactly the documents of their
--source files. Documents with errors are reported and compiled as invalid,
as the operator compiles them. A source allows Rego conditions only when
--rego-source names it, as a PolicySource does with rego.`,
		Args: cobra.ExactArgs(1),
		RunE: options.run,
	}
	command.Flags().StringArrayVar(&options.sources, "source", nil, "NAMESPACE/NAME=FILE assigning the documents of FILE to a PolicySource (repeatable)")
	command.Flags().StringArrayVar(&options.regoSources, "rego-source", nil, "NAMESPACE/NAME[=BUILTIN,...] allowing a source's Rego conditions to call the listed builtins, or the default builtins (repeatable)")
	registerOutputFlag(command, &options.output)
	return command
}

func (o *graphOptions) run(command *cobra.Command, args []string) error {
	if err := checkOutput(o.output); err != nil {
		return err
	}
	report, err := o.validate(command.InOrStdin(), args[0])
	if err != nil {
		return err
	}
	return writeValidationReport(command.OutOrStdout(), o.output, report)
}

// validate compiles the service in serviceFile against the documents
// the --source mappings assign. Every source is complete: it holds exactly
// the documents its files contain.
func (o *graphOptions) validate(stdin io.Reader, serviceFile string) (validationReport, error) {
	assignments, err := parseSourceFiles(serviceFile, o.sources)
	if err != nil {
		return validationReport{}, err
	}
	allowed, err := parseRegoSources(o.regoSources, assignments)
	if err != nil {
		return validationReport{}, err
	}
	data, err := readInput(stdin, serviceFile, maxInputBytes)
	if err != nil {
		return validationReport{}, err
	}
	report := validationReport{Diagnostics: []diagnostic{}}
	var service *api.AuthorizationService
	var config model.ServiceConfig
	var decoded bool
	report.Documents += yamlDocuments(data, func(number int, document []byte, err error) {
		switch {
		case err != nil:
			report.Diagnostics = append(report.Diagnostics, errorDiagnostic(serviceFile, number, nil, documentIdentity{}, reasonInvalidSyntax, err))
		case decoded:
			report.Diagnostics = append(report.Diagnostics, errorDiagnostic(serviceFile, number, nil, documentIdentity{}, reasonInvalidGraphInput, errors.New("the service file must hold one AuthorizationService")))
		default:
			decoded = true
			var diagnostics []diagnostic
			service, config, diagnostics = decodeServiceDocument(serviceFile, number, document)
			report.Diagnostics = append(report.Diagnostics, diagnostics...)
		}
	})
	if !decoded {
		report.Diagnostics = append(report.Diagnostics, errorDiagnostic(serviceFile, 1, nil, documentIdentity{}, reasonInvalidGraphInput, errors.New("the service file holds no AuthorizationService")))
	}
	sources := map[model.SourceKey]model.SourceObservation{}
	for _, assignment := range assignments {
		observation, found := sources[assignment.source]
		if !found {
			observation = model.SourceObservation{Instance: model.SourceInstance{Key: assignment.source}, Complete: true, Documents: map[model.Reference]model.DocumentState{}}
			if builtins, rego := allowed[assignment.source]; rego {
				observation.AllowedBuiltins = &builtins
			}
		}
		contents, readErr := readInput(stdin, assignment.file, maxInputBytes)
		if readErr != nil {
			return validationReport{}, readErr
		}
		report.Documents += yamlDocuments(contents, func(number int, document []byte, err error) {
			if err != nil {
				report.Diagnostics = append(report.Diagnostics, errorDiagnostic(assignment.file, number, new(assignment.source), documentIdentity{}, reasonInvalidSyntax, err))
				return
			}
			object := &unstructured.Unstructured{}
			if err := object.UnmarshalJSON(document); err != nil {
				report.Diagnostics = append(report.Diagnostics, errorDiagnostic(assignment.file, number, new(assignment.source), documentIdentity{}, model.ReasonInvalid, err))
				return
			}
			report.Diagnostics = append(report.Diagnostics, addSourceDocument(&observation, assignment.file, number, object)...)
		})
		sources[assignment.source] = observation
	}
	if service == nil {
		return report, nil
	}
	program, err := engine.Prepare(model.ServiceUID(service.UID), config, sources)
	if err != nil {
		report.Diagnostics = append(report.Diagnostics, errorDiagnostic(serviceFile, 1, nil, documentIdentity{}, reasonCompilationFailed, err))
		return report, nil
	}
	// Document issues are already reported against the files holding them.
	for _, issue := range program.Compilation.Diagnostics {
		if issue.Scope != api.IssueScopeDocument {
			report.Diagnostics = append(report.Diagnostics, diagnosticFromIssue(serviceFile, issue))
		}
	}
	for _, issue := range program.Content.Issues {
		report.Diagnostics = append(report.Diagnostics, diagnosticFromIssue(serviceFile, issue.Issue))
	}
	if program.Compilation.DiagnosticsTruncated {
		report.Diagnostics = append(report.Diagnostics, diagnostic{File: serviceFile, Document: 1, Severity: api.IssueSeverityWarning, Reason: reasonDiagnosticsTruncated, Message: "graph diagnostics exceeded the bounded output budget"})
	}
	return report, nil
}

type sourceFile struct {
	source model.SourceKey
	file   string
}

// parseSourceFiles parses NAMESPACE/NAME=FILE assignments. Standard input
// may back at most one file, the service file included.
func parseSourceFiles(serviceFile string, values []string) ([]sourceFile, error) {
	result := make([]sourceFile, 0, len(values))
	files := []string{serviceFile}
	for _, value := range values {
		name, file, found := strings.Cut(value, "=")
		if !found || file == "" {
			return nil, fmt.Errorf("invalid --source %q: expected NAMESPACE/NAME=FILE", value)
		}
		source, err := parseSourceKey(name)
		if err != nil {
			return nil, fmt.Errorf("invalid --source %q: %w", value, err)
		}
		result = append(result, sourceFile{source: source, file: file})
		files = append(files, file)
	}
	if countValue(files, "-") > 1 {
		return nil, errors.New("standard input may be specified only once")
	}
	return result, nil
}

// parseRegoSources parses NAMESPACE/NAME[=BUILTIN,...] values into each named
// source's allowed builtins: the listed ones, or the default builtins when none
// are listed. Every named source must be one a --source assigns, and every
// listed builtin one this release defines.
func parseRegoSources(values []string, assignments []sourceFile) (map[model.SourceKey]model.BuiltinSet, error) {
	result := make(map[model.SourceKey]model.BuiltinSet, len(values))
	for _, value := range values {
		name, list, listed := strings.Cut(value, "=")
		source, err := parseSourceKey(name)
		if err != nil {
			return nil, fmt.Errorf("invalid --rego-source %q: %w", value, err)
		}
		if !slices.ContainsFunc(assignments, func(assignment sourceFile) bool { return assignment.source == source }) {
			return nil, fmt.Errorf("--rego-source names %s/%s, which no --source assigns", source.Namespace, source.Name)
		}
		if !listed {
			result[source] = condition.DefaultBuiltins()
			continue
		}
		var builtins []string
		for builtin := range strings.SplitSeq(list, ",") {
			if builtin == "" {
				continue
			}
			if !condition.Defined(builtin) {
				return nil, fmt.Errorf("invalid --rego-source %q: %s isn't a builtin this release defines", value, builtin)
			}
			builtins = append(builtins, builtin)
		}
		result[source] = model.NewBuiltinSet(builtins)
	}
	return result, nil
}

// decodeServiceDocument decodes the AuthorizationService in a service file
// and returns it with its configuration, or the diagnostics that reject it.
func decodeServiceDocument(file string, number int, data []byte) (*api.AuthorizationService, model.ServiceConfig, []diagnostic) {
	object := &unstructured.Unstructured{}
	if err := object.UnmarshalJSON(data); err != nil {
		return nil, model.ServiceConfig{}, []diagnostic{errorDiagnostic(file, number, nil, documentIdentity{}, model.ReasonInvalid, err)}
	}
	identity := identityFrom(object)
	if object.GroupVersionKind() != api.GroupVersion.WithKind(authorizationServiceKind) {
		return nil, model.ServiceConfig{}, []diagnostic{errorDiagnostic(file, number, nil, identity, reasonInvalidGraphInput, errors.New("the service file must hold an authorization.zctx.io/v1alpha1 AuthorizationService"))}
	}
	service, config, errs := decodeService(object)
	return service, config, fieldDiagnostics(file, number, nil, identity, errs)
}

// addSourceDocument decodes one policy or RBAC document into observation.
// A nil observation reports that the document needs --source once its kind
// and metadata are valid.
func addSourceDocument(observation *model.SourceObservation, file string, number int, object *unstructured.Unstructured) []diagnostic {
	source := sourceKey(observation)
	identity := identityFrom(object)
	documentKind, supported := policyDocumentKind(object)
	if !supported {
		return []diagnostic{unsupportedDiagnostic(file, number, source, identity, object)}
	}
	if errs := validateMetadata(object, documentKind.Namespaced); len(errs) != 0 {
		return fieldDiagnostics(file, number, source, identity, errs)
	}
	if observation == nil {
		return []diagnostic{errorDiagnostic(file, number, nil, identity, reasonSourceRequired, errors.New("--source is required for policy and RBAC documents"))}
	}
	state := validation.DecodeDocument(observation.Instance, object)
	if _, exists := observation.Documents[state.Key.Reference()]; exists {
		return []diagnostic{duplicateDiagnostic(file, number, source, identity)}
	}
	observation.Documents[state.Key.Reference()] = state
	return issueDiagnostics(file, number, state.Issues)
}

// sourceKey returns the key of observation's source, or nil without one.
func sourceKey(observation *model.SourceObservation) *model.SourceKey {
	if observation == nil {
		return nil
	}
	return new(observation.Instance.Key)
}
