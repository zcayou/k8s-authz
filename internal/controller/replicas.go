package controller

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/engineclient"
	"github.com/zcayou/k8s-authz/internal/resources"
)

const engineWorkers = 8

// reconcilePods pushes program to every engine pod of owner whose opa
// container has started from startupDigest, and returns how many serve it.
// A pod that hasn't started yet or started from a former digest is left
// to its workload. A pod whose pushes keep failing for RemediationAfter
// is evicted.
func (r *AuthorizationServiceReconciler) reconcilePods(ctx context.Context, owner *api.AuthorizationService, startupDigest string, program engine.Program) (int32, error) {
	content := program.Content
	pods, err := r.enginePods(ctx, owner)
	if err != nil {
		return 0, err
	}
	pods = slices.DeleteFunc(pods, func(pod corev1.Pod) bool {
		return !pod.DeletionTimestamp.IsZero() || pod.Annotations[resources.AnnotationStartupDigest] != startupDigest || !engineStarted(&pod)
	})
	failures := make([]error, len(pods))
	if len(pods) != 0 {
		roots, err := r.serverRoots(ctx, owner)
		if err != nil {
			r.Recorder.Eventf(owner, nil, corev1.EventTypeWarning, "CAReadFailed", "Read", "Could not read serving CA: %v", err)
			return 0, err
		}
		state := sync.OnceValues(func() ([]byte, error) { return json.Marshal(content) })
		var group errgroup.Group
		group.SetLimit(engineWorkers)
		for index := range pods {
			group.Go(func() error {
				failures[index] = r.push(ctx, engineTarget(owner, &pods[index], roots), program, state)
				return ctx.Err()
			})
		}
		if err = group.Wait(); err != nil {
			return 0, err
		}
	}
	var current int32
	var errs []error
	for index, failure := range failures {
		if failure == nil {
			current++
			continue
		}
		r.Recorder.Eventf(&pods[index], owner, corev1.EventTypeWarning, "PushFailed", "Push", "Could not push policy revision %s: %v", content.Revision, failure)
		errs = append(errs, fmt.Errorf("push to Pod %s: %w", pods[index].Name, failure))
	}
	for _, pod := range r.remediationClock(owner, pods, failures) {
		errs = append(errs, r.evict(ctx, owner, pod))
	}
	return current, errors.Join(errs...)
}

// engineStarted reports whether pod's opa container has passed its startup
// probe, so OPA serves its management API.
func engineStarted(pod *corev1.Pod) bool {
	return slices.ContainsFunc(pod.Status.ContainerStatuses, func(status corev1.ContainerStatus) bool {
		return status.Name == resources.ContainerName && ptr.Deref(status.Started, false)
	})
}

// push installs program on target: its conditions module unless target
// already serves that module, then its state unless target already serves
// that revision. The module goes first: between the two writes the pod
// serves its former state with the new module, which defines every condition
// the two states share, and the conditions only the former state calls fail
// closed.
func (r *AuthorizationServiceReconciler) push(ctx context.Context, target engineclient.Target, program engine.Program, state func() ([]byte, error)) error {
	installed, err := r.Engines.Installed(ctx, target)
	if err != nil {
		return err
	}
	if installed.ConditionsDigest != program.Conditions.Digest {
		if err = r.Engines.PutConditions(ctx, target, program.Conditions); err != nil {
			return err
		}
	}
	if installed.Revision == program.Content.Revision {
		return nil
	}
	body, err := state()
	if err != nil {
		return err
	}
	return r.Engines.Replace(ctx, target, body)
}

// remediationClock replaces owner's failure clock with pods whose pushes
// failed, each keeping when it started failing, and returns those that have
// failed for RemediationAfter. A pod that is no longer pushed to,
// or that served the revision, leaves the clock.
func (r *AuthorizationServiceReconciler) remediationClock(owner *api.AuthorizationService, pods []corev1.Pod, failures []error) []*corev1.Pod {
	now := r.Clock.Now()
	key := client.ObjectKeyFromObject(owner)
	r.mutex.Lock()
	defer r.mutex.Unlock()
	previous := r.failing[key]
	failing := map[types.UID]time.Time{}
	var due []*corev1.Pod
	for index, failure := range failures {
		if failure == nil {
			continue
		}
		pod := &pods[index]
		since, found := previous[pod.UID]
		if !found {
			since = now
		}
		failing[pod.UID] = since
		if now.Sub(since) >= r.RemediationAfter {
			due = append(due, pod)
		}
	}
	if len(failing) == 0 {
		delete(r.failing, key)
		return due
	}
	if r.failing == nil {
		r.failing = map[types.NamespacedName]map[types.UID]time.Time{}
	}
	r.failing[key] = failing
	return due
}

// evict evicts pod through the Eviction API, so its PodDisruptionBudget
// keeps minimum serving capacity. The UID precondition keeps it from evicting
// a replacement with the same name.
func (r *AuthorizationServiceReconciler) evict(ctx context.Context, owner *api.AuthorizationService, pod *corev1.Pod) error {
	eviction := &policyv1.Eviction{ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: pod.Namespace}, DeleteOptions: &metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: new(pod.UID)}}}
	if err := r.SubResource("eviction").Create(ctx, pod, eviction); err != nil {
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	log.FromContext(ctx).Info("Evicted Pod after its policy pushes kept failing", "pod", client.ObjectKeyFromObject(pod))
	r.Recorder.Eventf(pod, owner, corev1.EventTypeWarning, "Evicted", "Evict", "Evicted Pod after its policy pushes failed for %s", r.RemediationAfter)
	return nil
}

// finishRuntimeKindSwitch deletes the former runtime kind's workload once
// the current workload reports minReadyReplicas ready pods. A current workload
// that is being deleted, as after a quick revert, is never trusted, and neither
// is one the service doesn't control, whose pods the listener doesn't select.
func (r *AuthorizationServiceReconciler) finishRuntimeKindSwitch(ctx context.Context, owner *api.AuthorizationService) error {
	key := types.NamespacedName{Namespace: owner.Namespace, Name: resources.Name(owner.Name)}
	var ready int32
	var former client.Object
	if owner.Spec.Runtime.Type == api.RuntimeTypeDeployment {
		var current appsv1.Deployment
		if err := r.Get(ctx, key, &current); err != nil || !current.DeletionTimestamp.IsZero() || !metav1.IsControlledBy(&current, owner) {
			return client.IgnoreNotFound(err)
		}
		ready, former = current.Status.ReadyReplicas, &appsv1.DaemonSet{}
	} else {
		var current appsv1.DaemonSet
		if err := r.Get(ctx, key, &current); err != nil || !current.DeletionTimestamp.IsZero() || !metav1.IsControlledBy(&current, owner) {
			return client.IgnoreNotFound(err)
		}
		ready, former = current.Status.NumberReady, &appsv1.Deployment{}
	}
	if ready < owner.Spec.Runtime.MinReadyReplicas {
		return nil
	}
	if err := r.Get(ctx, key, former); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !metav1.IsControlledBy(former, owner) || !former.GetDeletionTimestamp().IsZero() {
		return nil
	}
	if err := r.Delete(ctx, former, client.Preconditions{UID: new(former.GetUID())}, client.PropagationPolicy(metav1.DeletePropagationForeground)); err != nil {
		return client.IgnoreNotFound(err)
	}
	log.FromContext(ctx).Info("Deleted the former runtime kind's workload", "workload", client.ObjectKeyFromObject(former))
	r.Recorder.Eventf(owner, former, corev1.EventTypeNormal, "DeletedWorkload", "Delete", "Deleted the former runtime kind's workload %s", former.GetName())
	return nil
}

// enginePods lists the service's engine pods from the cache, by name.
func (r *AuthorizationServiceReconciler) enginePods(ctx context.Context, service *api.AuthorizationService) ([]corev1.Pod, error) {
	var list corev1.PodList
	if err := r.List(ctx, &list, client.InNamespace(service.Namespace), client.MatchingLabels(resources.ServiceUIDSelector(service.UID))); err != nil {
		return nil, err
	}
	slices.SortFunc(list.Items, func(a, b corev1.Pod) int { return strings.Compare(a.Name, b.Name) })
	return list.Items, nil
}

// EngineTarget addresses pod's management API, verified as service's engine.
func (r *AuthorizationServiceReconciler) EngineTarget(ctx context.Context, service *api.AuthorizationService, pod *corev1.Pod) (engineclient.Target, error) {
	roots, err := r.serverRoots(ctx, service)
	if err != nil {
		return engineclient.Target{}, err
	}
	return engineTarget(service, pod, roots), nil
}

// engineTarget addresses pod's management API, verified as service's serving
// certificate against roots.
func engineTarget(service *api.AuthorizationService, pod *corev1.Pod, roots *x509.CertPool) engineclient.Target {
	return engineclient.Target{Address: net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(int(resources.EnginePort))), ServerName: resources.ServerName(service.Namespace, service.Name), Roots: roots}
}
