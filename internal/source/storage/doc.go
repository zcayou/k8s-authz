// Package storage persists a policy source's view in Secrets, after Helm's
// Secret storage driver, so a restarted operator serves the view before its
// reader completes. The Secrets have type authorization.zctx.io/source-cache,
// live in the PolicySource's namespace and are controlled by it, so garbage
// collection removes them with it. Each holds a gzip'd chunk of a JSON array
// of the view's objects, its documents followed by a minimal v1 Namespace
// for each namespace whose labels it holds. Each is labeled with the source
// and its chunk index, and annotated with the view's origin, whether
// it collects namespace labels, and a digest of both the objects
// and that setting every chunk of one write shares. A write reads the chunks'
// metadata from a cache and changes nothing when they are exactly the view's
// chunks, numbered from zero and carrying its annotations, so a chunk deleted
// or relabeled out of band is rewritten and an unchanged view isn't. A restored
// view is exactly the view written, except that each document is decoded under
// the current schema with the fields it doesn't declare dropped.
package storage
