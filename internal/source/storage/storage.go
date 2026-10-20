package storage

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/validation"
)

// secretType marks the Secrets that hold a source's cached view.
const secretType corev1.SecretType = "authorization.zctx.io/source-cache"

var namespaceKind = corev1.SchemeGroupVersion.WithKind("Namespace")

const (
	sourceLabel               = "authorization.zctx.io/source"
	chunkLabel                = "authorization.zctx.io/cache-chunk"
	originAnnotation          = "authorization.zctx.io/origin"
	digestAnnotation          = "authorization.zctx.io/cache-digest"
	namespaceLabelsAnnotation = "authorization.zctx.io/namespace-labels"
	documentsKey              = "documents"
	// maxChunkBytes keeps each Secret well under the API server's 1 MiB object
	// limit.
	maxChunkBytes = 512 << 10
)

// encodedView is a view encoded for the cache.
type encodedView struct {
	// digest identifies the documents and namespace labels.
	digest          string
	origin          string
	namespaceLabels api.NamespaceLabels
	// chunks is the gzip'd JSON array of the documents and namespaces, split
	// into the data of one Secret each.
	chunks [][]byte
}

// encode encodes view as a gzip'd JSON array of its documents' objects,
// in reference order, followed by a minimal v1 Namespace for each namespace
// whose labels it holds, in name order.
func encode(view model.SourceObservation) (encodedView, error) {
	references := slices.SortedFunc(maps.Keys(view.Documents), func(a, b model.Reference) int { return cmp.Compare(a.String(), b.String()) })
	objects := make([]json.RawMessage, 0, len(references)+len(view.NamespaceLabels))
	for _, reference := range references {
		objects = append(objects, view.Documents[reference].Object)
	}
	namespaceLabels := api.NamespaceLabelsIgnore
	if view.CollectsNamespaceLabels {
		namespaceLabels = api.NamespaceLabelsCollect
	}
	for _, name := range slices.Sorted(maps.Keys(view.NamespaceLabels)) {
		namespace := &unstructured.Unstructured{}
		namespace.SetGroupVersionKind(namespaceKind)
		namespace.SetName(name)
		namespace.SetLabels(view.NamespaceLabels[name])
		encoded, err := namespace.MarshalJSON()
		if err != nil {
			return encodedView{}, fmt.Errorf("encode cached Namespace %s: %w", name, err)
		}
		objects = append(objects, encoded)
	}
	documents, err := json.Marshal(objects)
	if err != nil {
		return encodedView{}, fmt.Errorf("encode cached documents: %w", err)
	}
	var compressed bytes.Buffer
	archive := gzip.NewWriter(&compressed)
	if _, err := archive.Write(documents); err != nil {
		return encodedView{}, fmt.Errorf("compress cached documents: %w", err)
	}
	if err := archive.Close(); err != nil {
		return encodedView{}, fmt.Errorf("compress cached documents: %w", err)
	}
	return encodedView{
		digest:          digest(namespaceLabels, documents),
		origin:          view.Instance.Origin,
		namespaceLabels: namespaceLabels,
		chunks:          slices.Collect(slices.Chunk(compressed.Bytes(), maxChunkBytes)),
	}, nil
}

// Write stores view in chunk Secrets that owner controls. It reads their
// metadata through cached and changes nothing when they already hold view;
// otherwise it applies each chunk through writer and then deletes the chunks
// view doesn't need. Every chunk carries the view's digest, so a reader
// discards a write that stopped part way.
func Write(ctx context.Context, writer client.Client, cached client.Reader, owner *api.PolicySource, view model.SourceObservation) error {
	content, err := encode(view)
	if err != nil {
		return fmt.Errorf("encode PolicySource %s/%s cache: %w", owner.Namespace, owner.Name, err)
	}
	var list metav1.PartialObjectMetadataList
	list.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("SecretList"))
	if err := cached.List(ctx, &list, client.InNamespace(owner.Namespace), client.MatchingLabels{sourceLabel: owner.Name}); err != nil {
		return fmt.Errorf("list source cache Secrets for %s/%s: %w", owner.Namespace, owner.Name, err)
	}
	existing := slices.DeleteFunc(list.Items, func(secret metav1.PartialObjectMetadata) bool { return !controlledBy(&secret, owner.UID) })
	if holds(existing, owner.Name, content) {
		return nil
	}
	reference := metav1ac.OwnerReference().
		WithAPIVersion(api.GroupVersion.String()).WithKind("PolicySource").
		WithName(owner.Name).WithUID(owner.UID).WithController(true).WithBlockOwnerDeletion(true)
	written := make(map[string]bool, len(content.chunks))
	for index, chunk := range content.chunks {
		written[chunkName(owner.Name, index)] = true
		secret := corev1ac.Secret(chunkName(owner.Name, index), owner.Namespace).
			WithType(secretType).
			WithLabels(map[string]string{sourceLabel: owner.Name, chunkLabel: strconv.Itoa(index)}).
			WithAnnotations(map[string]string{originAnnotation: content.origin, digestAnnotation: content.digest, namespaceLabelsAnnotation: string(content.namespaceLabels)}).
			WithOwnerReferences(reference).
			WithData(map[string][]byte{documentsKey: chunk})
		if err := writer.Apply(ctx, secret, client.ForceOwnership); err != nil {
			return fmt.Errorf("apply source cache Secret %s/%s: %w", owner.Namespace, chunkName(owner.Name, index), err)
		}
	}
	for _, secret := range existing {
		if written[secret.Name] {
			continue
		}
		stale := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: secret.Namespace, Name: secret.Name}}
		if err := writer.Delete(ctx, stale, client.Preconditions{UID: &secret.UID}); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("delete source cache Secret %s/%s: %w", secret.Namespace, secret.Name, err)
		}
	}
	return nil
}

// holds reports whether secrets are exactly content's chunks of source's
// cache, each carrying content's origin, digest and namespace-label setting.
func holds(secrets []metav1.PartialObjectMetadata, source string, content encodedView) bool {
	if len(secrets) != len(content.chunks) {
		return false
	}
	names := make(map[string]metav1.PartialObjectMetadata, len(secrets))
	for _, secret := range secrets {
		names[secret.Name] = secret
	}
	for index := range content.chunks {
		secret, ok := names[chunkName(source, index)]
		if !ok || secret.Labels[chunkLabel] != strconv.Itoa(index) ||
			secret.Annotations[digestAnnotation] != content.digest || secret.Annotations[originAnnotation] != content.origin ||
			secret.Annotations[namespaceLabelsAnnotation] != string(content.namespaceLabels) {
			return false
		}
	}
	return true
}

// Read restores the view cached for instance from the Secrets its PolicySource
// controls. An empty instance.Origin accepts the origin the cache recorded,
// which the restored view's instance carries. Each document is decoded without
// the fields the current schema doesn't declare and keeps its cached bytes
// as its Object, so an unchanged view encodes to the digest already cached.
// Read reports false when there is no cache, and logs and discards a cache
// recorded under another origin or whose chunks don't form one write.
func Read(ctx context.Context, reader client.Reader, instance model.SourceInstance) (model.SourceObservation, bool, error) {
	secrets, err := list(ctx, reader, instance.Key.Namespace, instance.Key.Name, types.UID(instance.UID))
	if err != nil || len(secrets) == 0 {
		return model.SourceObservation{}, false, err
	}
	view, err := restore(secrets, instance)
	if err != nil {
		log.FromContext(ctx).Info("Discarded source cache", "namespace", instance.Key.Namespace, "name", instance.Key.Name, "reason", err.Error())
		return model.SourceObservation{}, false, nil
	}
	return view, true, nil
}

// restore joins the chunks of one write and decodes its documents
// and namespaces.
func restore(secrets []corev1.Secret, instance model.SourceInstance) (model.SourceObservation, error) {
	chunks := make([][]byte, len(secrets))
	expected := secrets[0].Annotations[digestAnnotation]
	namespaceLabels := api.NamespaceLabels(secrets[0].Annotations[namespaceLabelsAnnotation])
	instance.Origin = cmp.Or(instance.Origin, secrets[0].Annotations[originAnnotation])
	for _, secret := range secrets {
		switch {
		case secret.Annotations[originAnnotation] != instance.Origin:
			return model.SourceObservation{}, fmt.Errorf("cache Secret %s was collected from origin %q", secret.Name, secret.Annotations[originAnnotation])
		case secret.Annotations[digestAnnotation] != expected || api.NamespaceLabels(secret.Annotations[namespaceLabelsAnnotation]) != namespaceLabels:
			return model.SourceObservation{}, fmt.Errorf("cache Secret %s belongs to another write", secret.Name)
		}
		index, err := strconv.Atoi(secret.Labels[chunkLabel])
		if err != nil || index < 0 || index >= len(chunks) || chunks[index] != nil {
			return model.SourceObservation{}, fmt.Errorf("cache Secret %s has an unexpected chunk index", secret.Name)
		}
		chunks[index] = secret.Data[documentsKey]
	}
	archive, err := gzip.NewReader(bytes.NewReader(bytes.Join(chunks, nil)))
	if err != nil {
		return model.SourceObservation{}, fmt.Errorf("decompress cached documents: %w", err)
	}
	documents, err := io.ReadAll(archive)
	if err != nil {
		return model.SourceObservation{}, fmt.Errorf("decompress cached documents: %w", err)
	}
	if digest(namespaceLabels, documents) != expected {
		return model.SourceObservation{}, errors.New("cached documents don't match their digest")
	}
	var objects []json.RawMessage
	if err := json.Unmarshal(documents, &objects); err != nil {
		return model.SourceObservation{}, fmt.Errorf("decode cached documents: %w", err)
	}
	view := model.SourceObservation{Instance: instance, Complete: true, Documents: make(map[model.Reference]model.DocumentState, len(objects))}
	if namespaceLabels == api.NamespaceLabelsCollect {
		view.CollectsNamespaceLabels, view.NamespaceLabels = true, map[string]map[string]string{}
	}
	for _, encoded := range objects {
		object := &unstructured.Unstructured{}
		if err := object.UnmarshalJSON(encoded); err != nil {
			return model.SourceObservation{}, fmt.Errorf("decode cached document: %w", err)
		}
		if object.GroupVersionKind() == namespaceKind {
			if !view.CollectsNamespaceLabels {
				return model.SourceObservation{}, errors.New("cached Namespace in a view without namespace labels")
			}
			view.NamespaceLabels[object.GetName()] = object.GetLabels()
			continue
		}
		state := validation.DecodeCachedDocument(instance, object)
		state.Object = encoded
		view.Documents[state.Key.Reference()] = state
	}
	return view, nil
}

// list returns the cache Secrets the PolicySource with uid controls.
func list(ctx context.Context, reader client.Reader, namespace, name string, uid types.UID) ([]corev1.Secret, error) {
	var secrets corev1.SecretList
	if err := reader.List(ctx, &secrets, client.InNamespace(namespace), client.MatchingLabels{sourceLabel: name}); err != nil {
		return nil, fmt.Errorf("list source cache Secrets for %s/%s: %w", namespace, name, err)
	}
	return slices.DeleteFunc(secrets.Items, func(secret corev1.Secret) bool {
		return secret.Type != secretType || !controlledBy(&secret, uid)
	}), nil
}

// controlledBy reports whether the object with uid controls object.
func controlledBy(object metav1.Object, uid types.UID) bool {
	controller := metav1.GetControllerOfNoCopy(object)
	return controller != nil && controller.UID == uid
}

func chunkName(source string, index int) string {
	return source + "-source-cache-" + strconv.Itoa(index)
}

// digest identifies one write: its namespace-label setting and its encoded
// objects.
func digest(namespaceLabels api.NamespaceLabels, documents []byte) string {
	hash := sha256.New()
	hash.Write([]byte(namespaceLabels))
	hash.Write([]byte{0})
	hash.Write(documents)
	return hex.EncodeToString(hash.Sum(nil))
}
