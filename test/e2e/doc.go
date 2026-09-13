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

// Package e2e exercises the operator as config/ deploys it, with stock OPA
// engines behind a real API server's authorizer chain, on the Kind cluster
// make setup-test-e2e creates. It refuses to run unless the current kubeconfig
// context is that cluster.
//
// BeforeSuite builds and loads the manager image, creates the Secrets
// config/default mounts with certificates issued in memory, runs make install
// and make deploy, installs the baseline documents, and writes the API
// server's webhook configuration with render-caller-config. The remote source
// reads the same API server with a separate ServiceAccount's token.
//
// Every spec starts from the baseline and restores what it changes. After
// a failed spec the suite leaves the installation in place and records
// the cluster's state under artifacts/e2e-<run>/.
package e2e
