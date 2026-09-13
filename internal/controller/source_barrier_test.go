package controller

import (
	"context"
	"errors"
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/source"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("Source registration barrier", func() {
	It("waits only for an existing, undeleted source the endpoints read until the registry holds its UID", func(ctx SpecContext) {
		registry := startedRegistry()
		registered := localPolicySource("registered", "registered-uid")
		pending := localPolicySource("pending", "pending-uid")
		deleting := localPolicySource("deleting", "deleting-uid")
		deleting.DeletionTimestamp, deleting.Finalizers = &metav1.Time{Time: time.Now()}, []string{"test.example/hold"}
		unread := localPolicySource("unread", "unread-uid")
		outside := localPolicySource("outside", "outside-uid")
		outside.Namespace = "uncontrolled"
		service := utils.AuthorizationService(types.NamespacedName{Namespace: "default", Name: "authz"})
		service.Spec.Endpoints[0].SourceRefs = nil
		for _, name := range []string{"registered", "pending", "deleting", "missing"} {
			service.Spec.Endpoints[0].SourceRefs = append(service.Spec.Endpoints[0].SourceRefs, api.SourceRef{Namespace: "default", Name: name})
		}
		service.Spec.Endpoints = append(service.Spec.Endpoints, api.Endpoint{Name: "other", SourceRefs: []api.SourceRef{{Namespace: outside.Namespace, Name: outside.Name}}})

		// The control client behaves like a cache restricted to the default
		// namespace: it lists nothing outside it and fails to get from it.
		errUnknownNamespace := errors.New("unable to get: uncontrolled/outside because of unknown namespace for the cache")
		control := interceptor.NewClient(newPolicySourceFakeClient(registered, pending, deleting, unread, outside), interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if key.Namespace == outside.Namespace {
					return errUnknownNamespace
				}
				return c.Get(ctx, key, obj, opts...)
			},
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if err := c.List(ctx, list, opts...); err != nil {
					return err
				}
				if sources, ok := list.(*api.PolicySourceList); ok {
					sources.Items = slices.DeleteFunc(sources.Items, func(source api.PolicySource) bool { return source.Namespace == outside.Namespace })
				}
				return nil
			},
		})
		reconciler := newServiceReconciler(control)
		reconciler.Sources = registry
		all := func(model.Reference) bool { return true }
		registry.Pause(sourceKeyOf(registered), string(registered.UID), source.Settings{}, all)

		Expect(reconciler.unregisteredSource(ctx, service)).To(HaveValue(Equal(client.ObjectKeyFromObject(pending))))
		registry.Pause(sourceKeyOf(pending), "previous-uid", source.Settings{}, all)
		Expect(reconciler.unregisteredSource(ctx, service)).To(HaveValue(Equal(client.ObjectKeyFromObject(pending))))
		registry.Pause(sourceKeyOf(pending), string(pending.UID), source.Settings{}, all)
		Expect(reconciler.unregisteredSource(ctx, service)).To(BeNil())
	})
})
