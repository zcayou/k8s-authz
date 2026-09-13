// Package source holds each policy source's effective view and runs the reader
// that acquires it. The Registry is a manager runnable on every replica,
// and reader contexts derive from its Start.
//
// The registry alone holds source registration. Apply and Pause register
// a source under its PolicySource UID, which Registered reports, and only
// registered sources are in Snapshot. Restore seeds a view from the persistent
// cache while the registry has no complete view for the source.
//
// A source's view is its last complete observation, and no view expires.
// Acquisition failures, credential problems and pauses are reported as Health
// while the view keeps serving. Replacing a reader, or pausing, narrows
// the view to the new collection and keeps serving it; a new reader serves
// it until its first complete observation. Only a changed PolicySource UID,
// a reader built for another origin, or Remove discards it. Snapshot reports
// an Inert source, and one without a complete view, as an incomplete
// observation whose Failure carries the reason, and a complete view
// with the source's allowed builtins. Settings never touch the reader.
// Observations are immutable and shared. A reader runs until its context ends,
// and reports failures only as incomplete observations.
//
// Subscribers learn the key of every source whose registered UID, settings,
// health or documents change, once the change is visible. They're called
// on reader goroutines and while the registry serializes registrations, so they
// must not block for long. The registry knows nothing about persistence.
package source
