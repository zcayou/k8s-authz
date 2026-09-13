//go:build integration

package integration

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/zcayou/k8s-authz/test/utils"
)

const rulesNamespace = "rules"

// strict is the field validation every writer is expected to use.
var strict = client.FieldValidation(metav1.FieldValidationStrict)

// ensureNamespace creates namespace unless it exists. envtest runs no
// namespace controller, so namespaces are never removed.
func ensureNamespace(ctx context.Context, name string) {
	err := k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
	if !apierrors.IsAlreadyExists(err) {
		Expect(err).NotTo(HaveOccurred())
	}
}

// ruleDocument is a product document of kind in the rules namespace whose
// spec is the JSON spec.
func ruleDocument(kind, name, spec string) *unstructured.Unstructured {
	object := utils.Document(kind, rulesNamespace, name, spec)
	object.SetUID("")
	return object
}

// createAndRemove creates object with strict field validation and deletes
// it when the spec ends.
func createAndRemove(ctx context.Context, object client.Object) error {
	if err := k8sClient.Create(ctx, object, strict); err != nil {
		return err
	}
	DeferCleanup(func(ctx context.Context) {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, object))).To(Succeed())
	})
	return nil
}
