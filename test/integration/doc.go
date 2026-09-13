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

// Package integration tests the operator against one envtest API server
// and the pinned stock OPA binary.
//
// The manager runs as a leader-elected replica built through operator.Setup,
// with a fake engine management client injected. The specs assert by effect:
// every sample admitted and decoded strictly, the CRD validation rules,
// owned objects applied, repaired and recreated, pod templates rolled,
// policy pushed and status reported, pods evicted, runtime kinds switched,
// sources read, registered, cached and restored, remote sources composed,
// and the diagnostics endpoint authenticating and authorizing through the API
// server. The specs that compose a remote source start a second API server
// on first use. The engine specs run OPA from the engine ConfigMap and argument
// vector the operator renders, on loopback addresses.
//
// envtest runs no namespace or garbage-collection controller, so each spec
// deletes the AuthorizationServices and PolicySources it creates and restores
// the suite-wide files it changes, and the specs that change the shared CRDs
// run serially.
//
// The specs build only with the integration tag and need the envtest and OPA
// binaries, which make test-integration installs:
//
//	make test-integration
package integration
