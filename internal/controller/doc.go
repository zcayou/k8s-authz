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

// Package controller holds the operator's three controllers, all reading
// from the manager's cache except for Secret contents.
//
// The PolicySourceSupervisor runs on every replica and keeps no state of its
// own. It registers each PolicySource in the source registry, running
// or pausing its reader, and never writes to the API server. Until the registry
// holds a PolicySource's UID, it first restores the view cached for that UID,
// under the kubeconfig's origin when the credential is usable and under
// the recorded origin otherwise; a Paused source restores without reading its
// credential.
//
// The PolicySource and AuthorizationService controllers are leader-elected
// with warm caches. Once the registry holds a PolicySource's UID, the first
// projects registry health into its status and persists its view, rewriting
// the cache Secrets, whose metadata it watches, unless they already hold it.
// The second decodes a service, server-side applies each of its owned objects,
// rendering its engines' startup ConfigMap from the management identity
// and the service's client CA, compiles its policy and pushes the compiled
// state to each engine pod whose opa container has started from the current
// startup digest and doesn't already serve it. The digest leaves out the CA
// bundle, which OPA reloads in place. While the client CA can't be read,
// the ConfigMap and the workload are left as they are, and while the ConfigMap
// can't be applied, so is the workload; everything else goes ahead. Before
// it compiles, it waits, with status written, until the registry holds, under
// its current UID, every existing PolicySource the service's endpoints name.
// A pod whose pushes keep failing for RemediationAfter is evicted, subject
// to its PodDisruptionBudget; the failure clock is held in memory.
//
// Reconciles are event-driven: spec changes, owned objects, engine pods,
// including their opa container starting, CA bundle Secrets and ConfigMaps,
// management certificate and CA changes, and registry notifications, which
// reach the services whose endpoints read the changed source.
// The notification's cache List delays the registry's callbacks only while
// the caches sync at startup. A reconcile waiting on a registration returns
// without requeueing, because the registration notifies. Failures return
// errors, including failed applies and pushes, which the controller retries
// with its backoff until they succeed or the pod is evicted; an invalid spec
// or a policy that can't be prepared returns a terminal error. A service's
// status issues are its compiled policy's alone: a failure to prepare it sets
// Prepared, and failures to read a CA bundle, build or apply owned objects,
// or push are reported as Events.
package controller
