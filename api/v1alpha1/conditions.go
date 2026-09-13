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

package v1alpha1

// AuthorizationService condition types.
const (
	// ConditionPrepared reports whether the service's policy snapshot compiled
	// for the current spec and sources.
	ConditionPrepared = "Prepared"
	// ConditionReady reports whether at least minReadyReplicas engines serve
	// the desired revision under the current startup configuration.
	ConditionReady = "Ready"
	// ConditionPolicyHealthy reports whether the compiled policy has errors.
	ConditionPolicyHealthy = "PolicyHealthy"
)

// PolicySource condition types.
const (
	// ConditionSynchronized reports whether the source's latest acquisition
	// is complete. The source keeps serving its last complete view while it isn't.
	ConditionSynchronized = "Synchronized"
)

// Condition reasons.
const (
	// ReasonInvalid means the service's spec failed validation. The condition
	// message lists every field error.
	ReasonInvalid = "Invalid"
	// ReasonPrepared means the policy snapshot compiled.
	ReasonPrepared = "Prepared"
	// ReasonPreparationUnavailable means the policy snapshot could not
	// be compiled, or its sources are not yet registered.
	ReasonPreparationUnavailable = "PreparationUnavailable"
	// ReasonServing means at least minReadyReplicas engines serve the desired
	// revision.
	ReasonServing = "Serving"
	// ReasonInsufficientCapacity means fewer than minReadyReplicas engines serve
	// the desired revision.
	ReasonInsufficientCapacity = "InsufficientCapacity"
	// ReasonPolicyHealthy means the compiled policy has no errors.
	ReasonPolicyHealthy = "PolicyHealthy"
	// ReasonPolicyErrors means the compiled policy has errors, which status
	// issues list.
	ReasonPolicyErrors = "PolicyErrors"
	// ReasonSynchronized means the source's latest acquisition is complete.
	ReasonSynchronized = "Synchronized"
	// ReasonPending means the source hasn't completed its first acquisition.
	ReasonPending = "Pending"
	// ReasonPaused means the source's synchronization is Paused.
	ReasonPaused = "Paused"
	// ReasonInvalidCredential means the source's kubeconfig Secret is missing
	// or unusable. A reader already running keeps its credential.
	ReasonInvalidCredential = "InvalidCredential"
	// ReasonWatchFailing means a list or watch against the source failed
	// and hasn't succeeded since.
	ReasonWatchFailing = "WatchFailing"
	// ReasonIncompatibleSchema means a document CRD in the source doesn't
	// serve this API version.
	ReasonIncompatibleSchema = "IncompatibleSchema"
)
