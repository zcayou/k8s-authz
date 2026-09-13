package controller

import (
	"context"
	"fmt"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	apiac "github.com/zcayou/k8s-authz/api/v1alpha1/applyconfiguration/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/resources"
)

// writeStatus writes service's status. prepared is its prepared policy, or nil
// with failure saying why it isn't, and current counts the engine pods serving
// prepared under the current startup digest.
func (r *AuthorizationServiceReconciler) writeStatus(ctx context.Context, service *api.AuthorizationService, prepared *engine.Program, current int32, failure error) error {
	status := apiac.AuthorizationServiceStatus().WithObservedGeneration(service.Generation).WithCurrentReplicas(current)
	if desired := r.expectedReplicas(ctx, service); desired != nil {
		status.WithDesiredReplicas(*desired)
	}
	setCondition := func(name string, state metav1.ConditionStatus, reason, message string) {
		status.WithConditions(statusCondition(service.Status.Conditions, service.Generation, name, state, reason, message))
	}
	var issues []model.Issue
	var truncated bool
	switch {
	case prepared != nil:
		status.WithDesiredRevision(string(prepared.Content.Revision))
		issues = append(issues, prepared.Compilation.Diagnostics...)
		for _, issue := range prepared.Content.Issues {
			issues = append(issues, issue.Issue)
		}
		truncated = prepared.Compilation.DiagnosticsTruncated
		setCondition(api.ConditionPrepared, metav1.ConditionTrue, api.ReasonPrepared, "desired policy snapshot is prepared")
	case apierrors.IsInvalid(failure):
		setCondition(api.ConditionPrepared, metav1.ConditionFalse, api.ReasonInvalid, failure.Error())
	default:
		setCondition(api.ConditionPrepared, metav1.ConditionFalse, api.ReasonPreparationUnavailable, failure.Error())
	}
	pods, err := r.enginePods(ctx, service)
	if err != nil {
		return err
	}
	var ready int32
	for index := range pods {
		if resources.PodReady(&pods[index]) {
			ready++
		}
	}
	status.WithReadyReplicas(ready)
	switch {
	case prepared == nil:
		setCondition(api.ConditionReady, metav1.ConditionFalse, api.ReasonPreparationUnavailable, "desired policy could not be prepared")
	case current >= service.Spec.Runtime.MinReadyReplicas:
		setCondition(api.ConditionReady, metav1.ConditionTrue, api.ReasonServing, "at least minReadyReplicas engines serve the desired revision")
	default:
		setCondition(api.ConditionReady, metav1.ConditionFalse, api.ReasonInsufficientCapacity, "fewer than minReadyReplicas engines serve the desired revision")
	}
	converted, dropped := statusIssues(issues)
	status.WithIssues(converted...)
	if truncated || dropped {
		status.WithIssuesTruncated(true)
	}
	if prepared == nil {
		setCondition(api.ConditionPolicyHealthy, metav1.ConditionUnknown, api.ReasonPreparationUnavailable, "desired policy could not be prepared")
	} else if index := slices.IndexFunc(converted, func(issue *apiac.IssueApplyConfiguration) bool { return *issue.Severity == api.IssueSeverityError }); index >= 0 {
		setCondition(api.ConditionPolicyHealthy, metav1.ConditionFalse, api.ReasonPolicyErrors, *converted[index].Message)
	} else {
		setCondition(api.ConditionPolicyHealthy, metav1.ConditionTrue, api.ReasonPolicyHealthy, "no policy errors were observed")
	}
	configuration := apiac.AuthorizationService(service.Name, service.Namespace).WithStatus(status)
	if err := applyStatus(ctx, r.Client, configuration); err != nil {
		return fmt.Errorf("apply AuthorizationService %s/%s status: %w", service.Namespace, service.Name, err)
	}
	return nil
}

func (r *AuthorizationServiceReconciler) expectedReplicas(ctx context.Context, service *api.AuthorizationService) *int32 {
	if service.Spec.Runtime.Type == api.RuntimeTypeDeployment {
		return new(service.Spec.Runtime.Deployment.Replicas)
	}
	var workload appsv1.DaemonSet
	if err := r.Get(ctx, types.NamespacedName{Namespace: service.Namespace, Name: resources.Name(service.Name)}, &workload); err == nil && metav1.IsControlledBy(&workload, service) {
		return new(workload.Status.DesiredNumberScheduled)
	}
	return nil
}
