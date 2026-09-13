// Package resources builds the native Kubernetes apply configurations
// an AuthorizationService owns from the service itself: the engine ConfigMap,
// the listener Service, the PodDisruptionBudget and the Deployment or DaemonSet
// running stock OPA, whichever the runtime union selects. Every object carries
// the service's controller owner reference and is server-side applied under
// [FieldOwner], and explicit zero values retain their field ownership. The API
// server's single-controller rule is the ownership boundary.
//
// It is the single owner of the engine Pod's operand contract: its container,
// ports, mount paths, the stock OPA arguments of [PodLayout], the engine
// ConfigMap's keys and where each lands, and the pinned-image rule
// of [ValidateImage].
//
// The builders leave the listener's allocated addresses and node ports
// to the API server, which keeps them when an apply omits them. The workload
// selects its pods by service UID and runtime kind, so the two workloads
// never share pods during a runtime-kind switch. The pod template carries
// the digest of the engine ConfigMap's data other than its CA bundle
// in [AnnotationStartupDigest], so a startup change rolls the engines, while
// a CA bundle change reaches them in place because OPA reloads it.
//
// The service's Pod template and listener overrides are merged onto
// the generated objects with strategic merge, named lists by name, and their
// values win. Nothing in an override is rejected here: the API server validates
// the merged objects when they are applied. Builders perform no API reads.
package resources
