package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/resources"
	"github.com/zcayou/k8s-authz/internal/validation"
)

// decodeService returns service's configuration. It reports an invalid spec
// as an Invalid API error carrying every field error.
func decodeService(service *api.AuthorizationService) (model.ServiceConfig, error) {
	config, errs := validation.DecodeService(service)
	if len(errs) != 0 {
		return model.ServiceConfig{}, apierrors.NewInvalid(api.GroupVersion.WithKind("AuthorizationService").GroupKind(), service.Name, errs)
	}
	return config, nil
}

// applyOwned builds service's owned objects and applies each of them, so one
// failure doesn't hold back the others, and returns the startup digest
// of the engine pods to push to. While the client CA can't be read, the engine
// ConfigMap and the workload that starts from it are left as they are:
// the digest doesn't cover the CA bundle, which OPA reloads in place.
// The workload is also left as it is while the ConfigMap can't be applied,
// since its new pods would start from the former ConfigMap under the new
// digest.
func (r *AuthorizationServiceReconciler) applyOwned(ctx context.Context, service *api.AuthorizationService) (string, error) {
	certificate, err := r.ManagementCertificate.GetCertificate(nil)
	if err != nil {
		return "", err
	}
	roots := r.ManagementRoots.CurrentCABundleContent()
	input := resources.BuildInput{Service: service, EngineImage: r.EngineImage, DecisionLogs: r.DecisionLogs}
	input.Bootstrap, err = engine.NewBootstrap(model.ServiceUID(service.UID), roots, certificate.Leaf.Subject.CommonName)
	if err != nil {
		r.Recorder.Eventf(service, nil, corev1.EventTypeWarning, "ApplyFailed", "Build", "Could not build engine bootstrap: %v", err)
		return "", fmt.Errorf("build engine bootstrap: %w", err)
	}
	clientCA, caErr := r.caBundle(ctx, service.Namespace, service.Spec.TLS.Client.CARef)
	if caErr != nil {
		r.Recorder.Eventf(service, nil, corev1.EventTypeWarning, "CAReadFailed", "Read", "Could not read client CA: %v", caErr)
		caErr = fmt.Errorf("read client CA: %w", caErr)
	} else {
		input.CABundle = concatBundles(roots, clientCA)
	}
	owned, err := resources.Build(input)
	if err != nil {
		r.Recorder.Eventf(service, nil, corev1.EventTypeWarning, "ApplyFailed", "Build", "Could not build owned objects: %v", err)
		return "", errors.Join(caErr, fmt.Errorf("build owned objects: %w", err))
	}
	errs := []error{caErr}
	if owned.ConfigMap != nil {
		if err := r.apply(ctx, service, owned.ConfigMap); err != nil {
			errs = append(errs, err)
			owned.Deployment, owned.DaemonSet = nil, nil
		}
		owned.ConfigMap = nil
	}
	for _, object := range owned.Objects() {
		errs = append(errs, r.apply(ctx, service, object))
	}
	return owned.StartupDigest, errors.Join(errs...)
}

// concatBundles concatenates PEM bundles, once each, each ending in a newline.
func concatBundles(bundles ...[]byte) []byte {
	var result []byte
	for _, bundle := range slices.CompactFunc(bundles, bytes.Equal) {
		result = append(result, bundle...)
		if !bytes.HasSuffix(bundle, []byte("\n")) {
			result = append(result, '\n')
		}
	}
	return result
}

// serverRoots returns the roots the operator verifies service's engines with.
func (r *AuthorizationServiceReconciler) serverRoots(ctx context.Context, service *api.AuthorizationService) (*x509.CertPool, error) {
	bundle, err := r.caBundle(ctx, service.Namespace, service.Spec.TLS.Server.CARef)
	if err != nil {
		return nil, fmt.Errorf("read serving CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle) {
		return nil, errors.New("serving CA bundle holds no PEM certificates")
	}
	return roots, nil
}

// caBundle reads the PEM bundle ref names in namespace. Secrets are read
// directly, because they stay out of the cache.
func (r *AuthorizationServiceReconciler) caBundle(ctx context.Context, namespace string, ref api.CABundleRef) ([]byte, error) {
	if selector := ref.ConfigMapKeyRef; selector != nil {
		var config corev1.ConfigMap
		if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: selector.Name}, &config); err != nil {
			return nil, err
		}
		if bundle := config.Data[selector.Key]; bundle != "" {
			return []byte(bundle), nil
		}
		return nil, fmt.Errorf("no key %q in ConfigMap %s/%s", selector.Key, namespace, selector.Name)
	}
	selector := ref.SecretKeyRef
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: selector.Name}, &secret); err != nil {
		return nil, err
	}
	if bundle := secret.Data[selector.Key]; len(bundle) != 0 {
		return bundle, nil
	}
	return nil, fmt.Errorf("no key %q in Secret %s/%s", selector.Key, namespace, selector.Name)
}
