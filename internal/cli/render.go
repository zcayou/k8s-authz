package cli

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/resources"
)

const decisionPathPrefix = "/v0/data/authz/endpoints/"

type renderOptions struct {
	connection            *connection
	endpoint              string
	webhookServer         string
	authorizedTTL         time.Duration
	unauthorizedTTL       time.Duration
	serviceFile           string
	callerCertificate     string
	callerKey             string
	engineCA              string
	webhookKubeconfigPath string
	recoveryUsers         []string
	recoveryGroups        []string
	outputDirectory       string
}

func newRenderCallerConfigCommand() *cobra.Command {
	options := &renderOptions{}
	command := &cobra.Command{
		Use:   "render-caller-config (NAME | --service-file FILE) --endpoint ENDPOINT --webhook-server URL",
		Short: "Render kube-apiserver authorization caller configuration",
		Long: `Render-caller-config writes the webhook kubeconfig and AuthorizationConfiguration
with which kube-apiserver calls one endpoint of the AuthorizationService NAME,
read from the cluster, or of the AuthorizationService in --service-file.

The webhook's failurePolicy is the endpoint's whenEvaluationFails when it is
rendered, so render again after changing it. The AuthorizationConfiguration
holds the endpoint's webhook followed by Node and RBAC; to call several
endpoints, render each into its own directory and merge their webhook
authorizers into one configuration.`,
		Args: func(command *cobra.Command, args []string) error {
			if options.serviceFile != "" {
				return cobra.NoArgs(command, args)
			}
			return cobra.ExactArgs(1)(command, args)
		},
		RunE: options.run,
	}
	flags := command.Flags()
	flags.StringVar(&options.endpoint, "endpoint", "", "AuthorizationService endpoint name")
	flags.StringVar(&options.webhookServer, "webhook-server", "", "HTTPS base URL at which kube-apiserver reaches the AuthorizationService, without a path")
	flags.DurationVar(&options.authorizedTTL, "authorized-ttl", 5*time.Minute, "how long kube-apiserver caches Allow decisions; 0 disables caching")
	flags.DurationVar(&options.unauthorizedTTL, "unauthorized-ttl", 30*time.Second, "how long kube-apiserver caches Deny and NoOpinion decisions; 0 disables caching")
	flags.StringVar(&options.serviceFile, "service-file", "", "AuthorizationService YAML or JSON file, or - for standard input")
	flags.StringVar(&options.callerCertificate, "caller-certificate", "", "absolute kube-apiserver path of the client certificate it presents to the engines")
	flags.StringVar(&options.callerKey, "caller-key", "", "absolute kube-apiserver path of that certificate's private key")
	flags.StringVar(&options.engineCA, "engine-ca", "", "absolute kube-apiserver path of the CA bundle that verifies the engines")
	flags.StringVar(&options.webhookKubeconfigPath, "webhook-kubeconfig-path", "", "absolute kube-apiserver path of the rendered webhook kubeconfig")
	flags.StringArrayVar(&options.recoveryUsers, "recovery-user", nil, "user identity that bypasses the webhook (repeatable)")
	flags.StringArrayVar(&options.recoveryGroups, "recovery-group", nil, "group identity that bypasses the webhook (repeatable)")
	flags.StringVar(&options.outputDirectory, "output-dir", "", "directory for webhook.kubeconfig and authorization-config.yaml")
	options.connection = bindConnectionFlags(command)
	for _, name := range []string{"endpoint", "webhook-server", "caller-certificate", "caller-key", "engine-ca", "webhook-kubeconfig-path"} {
		_ = command.MarkFlagRequired(name)
	}
	options.connection.flags.VisitAll(func(flag *pflag.Flag) {
		command.MarkFlagsMutuallyExclusive("service-file", flag.Name)
	})
	return command
}

func (o *renderOptions) run(command *cobra.Command, args []string) error {
	if err := o.validateFlags(); err != nil {
		return err
	}
	var service *api.AuthorizationService
	var err error
	if o.serviceFile != "" {
		service, err = o.readService(command.InOrStdin())
	} else {
		service, err = o.getService(command.Context(), args[0])
	}
	if err != nil {
		return err
	}
	endpoint, err := resolveEndpoint(service, o.endpoint)
	if err != nil {
		return err
	}
	kubeconfig, authorization, err := o.render(service, endpoint)
	if err != nil {
		return err
	}
	if o.outputDirectory == "" {
		if _, err = fmt.Fprintf(command.OutOrStdout(), "%s---\n%s", kubeconfig, authorization); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		return nil
	}
	return writeCallerArtifacts(o.outputDirectory, kubeconfig, authorization)
}

func (o *renderOptions) validateFlags() error {
	server, err := url.Parse(o.webhookServer)
	if err != nil || server.Scheme != "https" || server.Host == "" || server.User != nil || server.Path != "" || server.RawQuery != "" || server.Fragment != "" {
		return errors.New("--webhook-server must be an HTTPS URL without credentials, path, query, or fragment")
	}
	if o.authorizedTTL < 0 || o.unauthorizedTTL < 0 {
		return errors.New("--authorized-ttl and --unauthorized-ttl must not be negative")
	}
	for name, value := range map[string]string{
		"--caller-certificate":      o.callerCertificate,
		"--caller-key":              o.callerKey,
		"--engine-ca":               o.engineCA,
		"--webhook-kubeconfig-path": o.webhookKubeconfigPath,
	} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s must be an absolute clean path", name)
		}
	}
	if len(o.recoveryUsers)+len(o.recoveryGroups) > 64 {
		return errors.New("recovery identities exceed the 64 match-condition limit")
	}
	for _, identity := range slices.Concat(o.recoveryUsers, o.recoveryGroups) {
		if identity == "" || !utf8.ValidString(identity) || strings.ContainsRune(identity, '\x00') {
			return errors.New("recovery identities must be nonempty valid UTF-8 without NUL")
		}
	}
	return nil
}

// readService strictly decodes the one AuthorizationService in the service
// file.
func (o *renderOptions) readService(stdin io.Reader) (*api.AuthorizationService, error) {
	data, err := readInput(stdin, o.serviceFile, maxInputBytes)
	if err != nil {
		return nil, err
	}
	var documents [][]byte
	var syntaxErr error
	yamlDocuments(data, func(_ int, document []byte, err error) {
		documents = append(documents, document)
		syntaxErr = cmp.Or(syntaxErr, err)
	})
	if syntaxErr != nil {
		return nil, fmt.Errorf("decode service file %q: %w", o.serviceFile, syntaxErr)
	}
	if len(documents) != 1 {
		return nil, fmt.Errorf("service file %q must contain exactly one document", o.serviceFile)
	}
	service, _, diagnostics := decodeServiceDocument(o.serviceFile, 1, documents[0])
	if len(diagnostics) != 0 {
		messages := make([]string, 0, len(diagnostics))
		for _, entry := range diagnostics {
			messages = append(messages, entry.fieldMessage())
		}
		return nil, fmt.Errorf("service file %q: %s", o.serviceFile, strings.Join(messages, "; "))
	}
	return service, nil
}

// getService reads the AuthorizationService name from the cluster. The API
// server has admitted it, so fields this release doesn't know are ignored.
func (o *renderOptions) getService(ctx context.Context, name string) (*api.AuthorizationService, error) {
	cluster, err := o.connection.connect()
	if err != nil {
		return nil, err
	}
	var service api.AuthorizationService
	if err = cluster.client.Get(ctx, client.ObjectKey{Namespace: cluster.namespace, Name: name}, &service); err != nil {
		return nil, fmt.Errorf("get AuthorizationService %s/%s: %w", cluster.namespace, name, err)
	}
	return &service, nil
}

func resolveEndpoint(service *api.AuthorizationService, name string) (api.Endpoint, error) {
	for _, endpoint := range service.Spec.Endpoints {
		if endpoint.Name == name {
			return endpoint, nil
		}
	}
	return api.Endpoint{}, fmt.Errorf("endpoint %q is not declared in spec", name)
}

// render returns the webhook kubeconfig and authorization configuration
// for endpoint of service. The kubeconfig verifies the engines as the listener
// Service's DNS name, whatever address --webhook-server reaches them at.
func (o *renderOptions) render(service *api.AuthorizationService, endpoint api.Endpoint) ([]byte, []byte, error) {
	const contextName = "k8s-authz"
	kubeconfig := clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{contextName: {
			Server:               o.webhookServer + decisionPathPrefix + endpoint.Name + "/decision",
			CertificateAuthority: o.engineCA,
			TLSServerName:        resources.ServerName(service.Namespace, service.Name),
		}},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{contextName: {
			ClientCertificate: o.callerCertificate,
			ClientKey:         o.callerKey,
		}},
		Contexts:       map[string]*clientcmdapi.Context{contextName: {Cluster: contextName, AuthInfo: contextName}},
		CurrentContext: contextName,
	}
	kubeconfigData, err := clientcmd.Write(kubeconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("encode webhook kubeconfig: %w", err)
	}
	matchConditions, err := recoveryMatchConditions(o.recoveryUsers, o.recoveryGroups)
	if err != nil {
		return nil, nil, err
	}
	cacheAllow := o.authorizedTTL > 0
	cacheDeny := o.unauthorizedTTL > 0
	configuration := apiserverv1.AuthorizationConfiguration{
		TypeMeta: metav1.TypeMeta{APIVersion: "apiserver.config.k8s.io/v1", Kind: "AuthorizationConfiguration"},
		Authorizers: []apiserverv1.AuthorizerConfiguration{
			{
				Type: string(apiserverv1.TypeWebhook),
				Name: authorizerName(service, endpoint),
				Webhook: &apiserverv1.WebhookConfiguration{
					AuthorizedTTL:                            metav1.Duration{Duration: o.authorizedTTL},
					CacheAuthorizedRequests:                  &cacheAllow,
					UnauthorizedTTL:                          metav1.Duration{Duration: o.unauthorizedTTL},
					CacheUnauthorizedRequests:                &cacheDeny,
					Timeout:                                  metav1.Duration{Duration: 3 * time.Second},
					SubjectAccessReviewVersion:               "v1",
					MatchConditionSubjectAccessReviewVersion: "v1",
					FailurePolicy:                            string(endpoint.WhenEvaluationFails),
					ConnectionInfo:                           apiserverv1.WebhookConnectionInfo{Type: apiserverv1.AuthorizationWebhookConnectionInfoTypeKubeConfigFile, KubeConfigFile: &o.webhookKubeconfigPath},
					MatchConditions:                          matchConditions,
				},
			},
			{Type: "Node", Name: "node"},
			{Type: "RBAC", Name: "rbac"},
		},
	}
	authorizationData, err := yaml.Marshal(configuration)
	if err != nil {
		return nil, nil, fmt.Errorf("encode authorization configuration: %w", err)
	}
	return kubeconfigData, authorizationData, nil
}

// authorizerName names the webhook authorizer of endpoint of service,
// uniquely among the endpoints of every AuthorizationService.
func authorizerName(service *api.AuthorizationService, endpoint api.Endpoint) string {
	return endpoint.Name + "." + service.Name + "." + service.Namespace + ".k8s-authz"
}

func recoveryMatchConditions(users, groups []string) ([]apiserverv1.WebhookMatchCondition, error) {
	users = sortedUnique(users)
	groups = sortedUnique(groups)
	conditions := make([]apiserverv1.WebhookMatchCondition, 0, len(users)+len(groups))
	for _, user := range users {
		quoted, err := json.Marshal(user)
		if err != nil {
			return nil, fmt.Errorf("quote recovery user: %w", err)
		}
		conditions = append(conditions, apiserverv1.WebhookMatchCondition{Expression: "request.user != " + string(quoted)})
	}
	for _, group := range groups {
		quoted, err := json.Marshal(group)
		if err != nil {
			return nil, fmt.Errorf("quote recovery group: %w", err)
		}
		conditions = append(conditions, apiserverv1.WebhookMatchCondition{Expression: "!(" + string(quoted) + " in request.groups)"})
	}
	return conditions, nil
}

func sortedUnique(values []string) []string {
	result := slices.Clone(values)
	slices.Sort(result)
	return slices.Compact(result)
}

func writeCallerArtifacts(directory string, kubeconfig, authorization []byte) error {
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return fmt.Errorf("create output directory %q: %w", directory, err)
	}
	for _, artifact := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{{"webhook.kubeconfig", kubeconfig, 0o600}, {"authorization-config.yaml", authorization, 0o644}} {
		path := filepath.Join(directory, artifact.name)
		if err := writeFileAtomically(path, artifact.data, artifact.mode); err != nil {
			return fmt.Errorf("write %q: %w", path, err)
		}
	}
	return nil
}

func writeFileAtomically(path string, data []byte, mode os.FileMode) (resultErr error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		if removeErr := os.Remove(temporaryPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) && resultErr == nil {
			resultErr = removeErr
		}
	}()
	if err = temporary.Chmod(mode); err == nil {
		_, err = temporary.Write(data)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
