// Package kubernetes acquires one Kubernetes policy source. NewCollection
// normalizes a PolicySource's collection, and Collection.Collects
// and Collection.CollectsNamespace report which documents and namespace labels
// it covers, for the reader and for a paused source's view alike. NewReader
// builds one filtered informer per kind, namespace and name its collection
// selects, dropping queries a broader one covers, so credentials scoped by RBAC
// resourceNames can list and watch. A collection that reads namespace labels
// adds one informer for every namespace when a range selects "*", otherwise one
// per named namespace, keeping only names and labels. Objects are decoded
// as they enter the informer caches, and changes coalesce into one emission
// of the whole view once every informer has synced. Informers own list
// and watch recovery and keep their stores while disconnected. A failed list
// or watch, before or after the initial sync, is reported as WatchFailing until
// that informer's next successful list or watch. A document CRD that doesn't
// serve this API version is reported as IncompatibleSchema. ParseKubeconfig
// accepts self-contained HTTPS credentials, and Origin identifies an API server
// without them.
package kubernetes
