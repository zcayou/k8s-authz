//go:build integration

package integration

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	kubernetessource "github.com/zcayou/k8s-authz/internal/source/kubernetes"
	"github.com/zcayou/k8s-authz/internal/validation"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("Samples", func() {
	It("are admitted unchanged and decode strictly", func(ctx SpecContext) {
		objects := samples()
		Expect(objects).NotTo(BeEmpty())
		type shippedSource struct {
			key        model.SourceKey
			collection kubernetessource.Collection
		}
		var sources []shippedSource
		var documents []*unstructured.Unstructured
		for _, object := range objects {
			description := object.GetKind() + " " + object.GetNamespace() + "/" + object.GetName()
			if object.GetNamespace() != "" {
				ensureNamespace(ctx, object.GetNamespace())
			}
			if object.GroupVersionKind() == corev1.SchemeGroupVersion.WithKind("Namespace") {
				ensureNamespace(ctx, object.GetName())
				continue
			}
			Expect(createAndRemove(ctx, object)).To(Succeed(), description)
			switch object.GroupVersionKind() {
			case api.GroupVersion.WithKind("AuthorizationService"):
				var service api.AuthorizationService
				Expect(validation.DecodeStrict(object, &service)).To(BeEmpty(), description)
				_, errs := validation.DecodeService(&service)
				Expect(errs).To(BeEmpty(), description)
			case api.GroupVersion.WithKind("PolicySource"):
				var source api.PolicySource
				Expect(validation.DecodeStrict(object, &source)).To(BeEmpty(), description)
				sources = append(sources, shippedSource{model.SourceKey{Namespace: source.Namespace, Name: source.Name}, kubernetessource.NewCollection(source.Spec)})
			default:
				documents = append(documents, object)
			}
		}
		for _, object := range documents {
			description := object.GetKind() + " " + object.GetNamespace() + "/" + object.GetName()
			gvk := object.GroupVersionKind()
			index := slices.IndexFunc(sources, func(source shippedSource) bool {
				return source.collection.Collects(model.Reference{Source: source.key, Group: gvk.Group, Kind: gvk.Kind, Namespace: object.GetNamespace(), Name: object.GetName()})
			})
			Expect(index).NotTo(Equal(-1), "no shipped source collects %s", description)
			state := validation.DecodeDocument(model.SourceInstance{Key: sources[index].key}, object)
			Expect(state.Document).NotTo(BeNil(), "%s: %v", description, state.Issues)
		}
	})
})

// samples reads every document in config/samples' YAML files except
// the kustomization.
func samples() []*unstructured.Unstructured {
	GinkgoHelper()
	root, err := utils.RepositoryPath("config", "samples")
	Expect(err).NotTo(HaveOccurred())
	files, err := filepath.Glob(filepath.Join(root, "*.yaml"))
	Expect(err).NotTo(HaveOccurred())
	files = slices.DeleteFunc(files, func(file string) bool { return filepath.Base(file) == "kustomization.yaml" })
	var objects []*unstructured.Unstructured
	for _, file := range files {
		content, err := os.Open(file)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(content.Close)
		decoder := utilyaml.NewYAMLOrJSONDecoder(content, 4096)
		for {
			object := &unstructured.Unstructured{}
			err := decoder.Decode(&object.Object)
			if errors.Is(err, io.EOF) {
				break
			}
			Expect(err).NotTo(HaveOccurred(), file)
			if len(object.Object) != 0 {
				objects = append(objects, object)
			}
		}
	}
	return objects
}
