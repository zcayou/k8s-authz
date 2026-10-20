/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/source"
	"github.com/zcayou/k8s-authz/internal/source/storage"
	"github.com/zcayou/k8s-authz/test/utils"
)

func synchronizedCondition(status api.PolicySourceStatus) *metav1.Condition {
	return apimeta.FindStatusCondition(status.Conditions, api.ConditionSynchronized)
}

var _ = Describe("PolicySource Controller", func() {
	var registry *source.Registry

	BeforeEach(func() {
		registry = startedRegistry()
	})

	reconcileStatus := func(ctx context.Context, controlClient client.Client, object client.Object) {
		GinkgoHelper()
		_, err := newPolicySourceReconciler(controlClient, registry).Reconcile(ctx, policySourceRequestFor(object))
		Expect(err).NotTo(HaveOccurred())
	}

	It("reports Pending until the first complete observation", func(ctx SpecContext) {
		object := localPolicySource("pending", "source-pending")
		controlClient := newPolicySourceFakeClient(object)
		runReader(registry, object)
		reconcileStatus(ctx, controlClient, object)

		status := observedPolicySourceStatus(ctx, controlClient, object)
		Expect(status.ObservedGeneration).To(Equal(object.Generation))
		Expect(status.Conditions).To(ConsistOf(SatisfyAll(
			HaveField("Type", api.ConditionSynchronized),
			HaveField("Status", metav1.ConditionUnknown),
			HaveField("Reason", api.ReasonPending),
		)))
		Expect(status.LastAdmittedTime).To(BeNil())
		Expect(status.Issues).To(BeEmpty())
	})

	It("reports Synchronized with the admission time of a complete view", func(ctx SpecContext) {
		object := localPolicySource("synchronized", "source-synchronized")
		controlClient := newPolicySourceFakeClient(object)
		_, emit := runReader(registry, object)
		before := time.Now()
		emit(completeView(sourceInstance(object), "workloads"))
		after := time.Now()
		reconcileStatus(ctx, controlClient, object)

		status := observedPolicySourceStatus(ctx, controlClient, object)
		Expect(status.ObservedGeneration).To(Equal(object.Generation))
		Expect(synchronizedCondition(status)).To(SatisfyAll(
			HaveField("Status", metav1.ConditionTrue),
			HaveField("Reason", api.ReasonSynchronized),
		))
		// The status holds the admission time to the second.
		Expect(status.LastAdmittedTime.Time).To(And(BeTemporally(">=", before.Truncate(time.Second)), BeTemporally("<=", after)))
	})

	It("reports WatchFailing in its condition while retaining the admitted view", func(ctx SpecContext) {
		object := localPolicySource("watch-failing", "source-watch-failing")
		controlClient := newPolicySourceFakeClient(object)
		_, emit := runReader(registry, object)
		emit(completeView(sourceInstance(object), "workloads"))
		admitted := registry.Health(sourceKeyOf(object)).LastAdmitted
		emit(model.SourceObservation{Instance: sourceInstance(object), Failure: model.Failure{
			Reason: api.ReasonWatchFailing, Message: "list or watch policies: forbidden",
		}})
		reconcileStatus(ctx, controlClient, object)

		status := observedPolicySourceStatus(ctx, controlClient, object)
		Expect(synchronizedCondition(status)).To(SatisfyAll(
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", api.ReasonWatchFailing),
			HaveField("Message", ContainSubstring("forbidden")),
		))
		Expect(status.Issues).To(BeEmpty())
		Expect(status.LastAdmittedTime.Time).To(BeTemporally("==", admitted.Truncate(time.Second)))
		Expect(registry.Snapshot()[sourceKeyOf(object)].Documents).To(HaveLen(1))
	})

	It("reports IncompatibleSchema without an admission time", func(ctx SpecContext) {
		object := localPolicySource("schema-mismatch", "source-schema-mismatch")
		controlClient := newPolicySourceFakeClient(object)
		_, emit := runReader(registry, object)
		emit(model.SourceObservation{Instance: sourceInstance(object), Failure: model.Failure{
			Reason: api.ReasonIncompatibleSchema, Message: "CRD policies.authorization.zctx.io: version v1alpha1 is not served",
		}})
		reconcileStatus(ctx, controlClient, object)

		status := observedPolicySourceStatus(ctx, controlClient, object)
		Expect(synchronizedCondition(status)).To(SatisfyAll(
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", api.ReasonIncompatibleSchema),
		))
		Expect(status.LastAdmittedTime).To(BeNil())
	})

	It("reports Paused without an issue", func(ctx SpecContext) {
		object := localPolicySource("paused", "source-paused")
		controlClient := newPolicySourceFakeClient(object)
		registry.Pause(sourceKeyOf(object), string(object.UID), source.Settings{}, utils.Coverage{})
		reconcileStatus(ctx, controlClient, object)

		status := observedPolicySourceStatus(ctx, controlClient, object)
		Expect(synchronizedCondition(status)).To(SatisfyAll(
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", api.ReasonPaused),
		))
		Expect(status.Issues).To(BeEmpty())
	})

	It("keeps the stored admission time of a restored view", func(ctx SpecContext) {
		admitted := metav1.NewTime(time.Date(2026, time.September, 13, 11, 0, 0, 0, time.UTC))
		object := localPolicySource("restored", "source-restored")
		object.Status.LastAdmittedTime = &admitted
		controlClient := newPolicySourceFakeClient(object)
		instance := sourceInstance(object)
		registry.Restore(completeView(instance, "workloads"))
		registry.Pause(sourceKeyOf(object), string(object.UID), source.Settings{}, utils.Coverage{})
		reconcileStatus(ctx, controlClient, object)

		Expect(observedPolicySourceStatus(ctx, controlClient, object).LastAdmittedTime.Time).To(BeTemporally("==", admitted.Time))
	})

	It("leaves a recreated PolicySource alone until its UID is registered, without its former status or view", func(ctx SpecContext) {
		former := localPolicySource("recreated", "source-former")
		_, emit := runReader(registry, former)
		emit(completeView(sourceInstance(former), "workloads"))
		object := localPolicySource("recreated", "source-recreated")
		controlClient := newPolicySourceFakeClient(object)
		reconcileStatus(ctx, controlClient, object)
		Expect(observedPolicySourceStatus(ctx, controlClient, object)).To(BeZero())

		runReader(registry, object)
		reconcileStatus(ctx, controlClient, object)
		status := observedPolicySourceStatus(ctx, controlClient, object)
		Expect(synchronizedCondition(status)).To(HaveField("Reason", api.ReasonPending))
		Expect(status.LastAdmittedTime).To(BeNil())
		var secrets corev1.SecretList
		Expect(controlClient.List(ctx, &secrets, client.InNamespace(object.Namespace))).To(Succeed())
		Expect(secrets.Items).To(BeEmpty())
	})

	It("persists a complete view", func(ctx SpecContext) {
		object := localPolicySource("persisted", "source-persisted")
		controlClient := newPolicySourceFakeClient(object)
		_, emit := runReader(registry, object)
		emit(completeView(sourceInstance(object), "workloads"))
		reconcileStatus(ctx, controlClient, object)

		var secrets corev1.SecretList
		Expect(controlClient.List(ctx, &secrets, client.InNamespace(object.Namespace))).To(Succeed())
		Expect(secrets.Items).To(ConsistOf(HaveField("Type", corev1.SecretType("authorization.zctx.io/source-cache"))))
		restored, found, err := storage.Read(ctx, controlClient, sourceInstance(object))
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(restored.Documents).To(HaveKey(policyDocument(sourceInstance(object), "workloads").Key.Reference()))
	})

	It("bounds and deterministically orders source diagnostics, errors first", func() {
		issues := make([]model.Issue, 0, maximumStatusIssues+4)
		for index := range maximumStatusIssues + 3 {
			issues = append(issues, model.Issue{
				Severity: api.IssueSeverityWarning,
				Reason:   model.IssueReason(fmt.Sprintf("Reason%03d", maximumStatusIssues+3-index)),
				Message:  "diagnostic",
				Scope:    api.IssueScopeDocument,
			})
		}
		issues = append(issues, model.Issue{Severity: api.IssueSeverityError, Reason: model.ReasonMissingReference, Message: "binding is absent", Scope: api.IssueScopeUse})
		converted, truncated := statusIssues(issues)
		Expect(truncated).To(BeTrue())
		Expect(converted).To(HaveLen(maximumStatusIssues))
		Expect(converted[0].Severity).To(HaveValue(Equal(api.IssueSeverityError)))
		Expect(converted[1].Reason).To(HaveValue(Equal("Reason001")))
		Expect(converted[len(converted)-1].Reason).To(HaveValue(Equal("Reason127")))
	})
})
