package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/cache"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/validation"
)

var (
	crdKind     = apiextensionsv1.SchemeGroupVersion.WithKind("CustomResourceDefinition")
	crdResource = apiextensionsv1.SchemeGroupVersion.WithResource("customresourcedefinitions")
)

// Reader keeps one informer for each query its collection plans, plus one
// for each document kind's CRD, and emits the source's view whenever any
// of them changes. It runs once.
type Reader struct {
	instance   model.SourceInstance
	collection Collection
	documents  []*collectionInformer
	schemas    []*collectionInformer
	// changed holds at most one pending view assembly, so any number of informer
	// changes coalesce into one.
	changed chan struct{}
}

type collectionInformer struct {
	query    collectionQuery
	store    cache.Store
	informer cache.Controller
	failure  atomic.Pointer[error]
}

// document is what a document informer stores in place of the object.
type document struct {
	metav1.ObjectMeta
	state model.DocumentState
}

// schemaState is what a CRD informer stores in place of the CRD: whether
// the CRD serves this API version.
type schemaState struct {
	metav1.ObjectMeta
	err error
}

// NewReader builds the informers for collection without performing network I/O.
func NewReader(client dynamic.Interface, instance model.SourceInstance, collection Collection) *Reader {
	reader := &Reader{instance: instance, collection: collection, changed: make(chan struct{}, 1)}
	queries := collectionQueries(collection)
	var schemas []collectionQuery
	for _, query := range queries {
		name := query.resource.Resource + "." + query.resource.Group
		if query.resource.Group == api.GroupVersion.Group && !slices.ContainsFunc(schemas, func(schema collectionQuery) bool { return schema.name == name }) {
			schemas = append(schemas, collectionQuery{kind: crdKind, resource: crdResource, name: name})
		}
	}
	reader.documents = reader.newInformers(client, queries, reader.ingest)
	reader.schemas = reader.newInformers(client, schemas, observeSchema)
	return reader
}

// Collects reports whether the reader's collection covers reference.
func (r *Reader) Collects(reference model.Reference) bool {
	return r.collection.Collects(reference)
}

// Run emits the source's view after every informer change until ctx ends.
// Informers own list and watch recovery.
func (r *Reader) Run(ctx context.Context, emit func(model.SourceObservation)) {
	informers := slices.Concat(r.documents, r.schemas)
	synced := make([]cache.InformerSynced, 0, len(informers))
	var workers sync.WaitGroup
	defer workers.Wait()
	for _, collection := range informers {
		synced = append(synced, collection.informer.HasSynced)
		workers.Go(func() { collection.informer.RunWithContext(ctx) })
	}
	workers.Go(func() {
		if cache.WaitForCacheSync(ctx.Done(), synced...) {
			r.trigger()
		}
	})
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.changed:
			if observation, ready := r.observe(); ready && ctx.Err() == nil {
				emit(observation)
			}
		}
	}
}

// trigger requests a view assembly unless one is already pending.
func (r *Reader) trigger() {
	select {
	case r.changed <- struct{}{}:
	default:
	}
}

// observe assembles the view from the informer stores. It isn't ready until
// every informer has synced, unless a list or watch is failing.
func (r *Reader) observe() (model.SourceObservation, bool) {
	informers := slices.Concat(r.documents, r.schemas)
	if err := watchFailure(informers); err != nil {
		return r.failure(api.ReasonWatchFailing, err), true
	}
	if slices.ContainsFunc(informers, func(collection *collectionInformer) bool { return !collection.informer.HasSynced() }) {
		return model.SourceObservation{}, false
	}
	if err := compatibleSchemas(r.schemas); err != nil {
		return r.failure(api.ReasonIncompatibleSchema, err), true
	}
	observation := model.SourceObservation{Instance: r.instance, Complete: true, Documents: map[model.Reference]model.DocumentState{}}
	// Queries that overlap without one covering the other hold the same object;
	// the first query's copy is kept.
	for _, collection := range r.documents {
		for _, item := range collection.store.List() {
			stored, ok := item.(*document)
			if !ok {
				continue
			}
			state := stored.state
			reference := state.Key.Reference()
			if _, found := observation.Documents[reference]; !found {
				observation.Documents[reference] = state
			}
		}
	}
	return observation, true
}

func (r *Reader) failure(reason string, err error) model.SourceObservation {
	return model.SourceObservation{Instance: r.instance, Failure: model.Failure{Reason: reason, Message: err.Error()}}
}

// newInformers builds each informer from a ListWatch that records the outcome
// of every list and watch request, so failures after the initial sync remain
// visible until the reflector's next successful request.
func (r *Reader) newInformers(client dynamic.Interface, queries []collectionQuery, transform cache.TransformFunc) []*collectionInformer {
	result := make([]*collectionInformer, 0, len(queries))
	for _, query := range queries {
		collection := &collectionInformer{query: query}
		resource := client.Resource(query.resource).Namespace(query.namespace)
		observe := func(err error) {
			if collection.observe(err) {
				r.trigger()
			}
		}
		listWatch := &cache.ListWatch{
			ListWithContextFunc: func(ctx context.Context, options metav1.ListOptions) (runtime.Object, error) {
				query.restrict(&options)
				list, err := resource.List(ctx, options)
				observe(err)
				return list, err
			},
			WatchFuncWithContext: func(ctx context.Context, options metav1.ListOptions) (watch.Interface, error) {
				query.restrict(&options)
				watcher, err := resource.Watch(ctx, options)
				observe(err)
				return watcher, err
			},
		}
		// The expected kind names the informer in client-go's logs.
		objectType := &unstructured.Unstructured{}
		objectType.SetGroupVersionKind(query.kind)
		collection.store, collection.informer = cache.NewInformerWithOptions(cache.InformerOptions{
			ListerWatcher: cache.ToListWatcherWithWatchListSemantics(listWatch, client),
			ObjectType:    objectType,
			Handler: cache.ResourceEventHandlerFuncs{
				AddFunc:    func(any) { r.trigger() },
				UpdateFunc: func(any, any) { r.trigger() },
				DeleteFunc: func(any) { r.trigger() },
			},
			Transform: transform,
		})
		result = append(result, collection)
	}
	return result
}

// observe records the outcome of one list or watch request and reports whether
// it changed the collection's health.
func (c *collectionInformer) observe(err error) bool {
	switch {
	case err == nil:
		return c.failure.Swap(nil) != nil
	case apierrors.IsResourceExpired(err) || apierrors.IsGone(err):
		// The reflector relists at once; an expired resource version is not a failure.
		return false
	}
	c.failure.Store(&err)
	return true
}

func watchFailure(informers []*collectionInformer) error {
	var failures []error
	for _, collection := range informers {
		if err := collection.failure.Load(); err != nil {
			failures = append(failures, fmt.Errorf("list or watch %s: %w", collection.query.resource, *err))
		}
	}
	return errors.Join(failures...)
}

// ingest is the document informers' transform. It decodes an acquired object
// into its document state, stripping the object's managed fields
// and last-applied configuration and keeping the canonical JSON of what remains
// as the state's Object. A document that doesn't decode is stored with its
// issue, so it can't stall the informer's sync.
func (r *Reader) ingest(item any) (any, error) {
	object, ok := item.(*unstructured.Unstructured)
	if !ok {
		return item, nil
	}
	object.SetManagedFields(nil)
	if annotations := object.GetAnnotations(); annotations[corev1.LastAppliedConfigAnnotation] != "" {
		delete(annotations, corev1.LastAppliedConfigAnnotation)
		object.SetAnnotations(annotations)
	}
	// encoding/json sorts map keys, so the encoding is canonical.
	encoded, err := json.Marshal(object.Object)
	if err != nil {
		return nil, fmt.Errorf("encode object: %w", err)
	}
	state := validation.DecodeDocument(r.instance, object)
	state.Object = encoded
	return &document{ObjectMeta: identity(object), state: state}, nil
}

func observeSchema(item any) (any, error) {
	object, ok := item.(*unstructured.Unstructured)
	if !ok {
		return item, nil
	}
	var crd apiextensionsv1.CustomResourceDefinition
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &crd)
	if err == nil {
		err = compatibleSchema(&crd)
	}
	return &schemaState{ObjectMeta: identity(object), err: err}, nil
}

func identity(object *unstructured.Unstructured) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: object.GetNamespace(), Name: object.GetName(), UID: object.GetUID(), ResourceVersion: object.GetResourceVersion()}
}

func compatibleSchemas(schemas []*collectionInformer) error {
	for _, collection := range schemas {
		items := collection.store.List()
		if len(items) == 0 {
			return fmt.Errorf("CRD %s is not installed", collection.query.name)
		}
		if state, ok := items[0].(*schemaState); ok && state.err != nil {
			return fmt.Errorf("CRD %s: %w", collection.query.name, state.err)
		}
	}
	return nil
}

// compatibleSchema rejects a document CRD that doesn't serve this API
// version, because the operator reads documents only through it.
func compatibleSchema(crd *apiextensionsv1.CustomResourceDefinition) error {
	if !slices.ContainsFunc(crd.Spec.Versions, func(version apiextensionsv1.CustomResourceDefinitionVersion) bool {
		return version.Name == api.GroupVersion.Version && version.Served
	}) {
		return fmt.Errorf("version %s is not served", api.GroupVersion.Version)
	}
	return nil
}
