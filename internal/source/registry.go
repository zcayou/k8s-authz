package source

import (
	"context"
	"errors"
	"sync"
	"time"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
)

// Reader acquires the documents of one source.
type Reader interface {
	// Run emits observations until ctx is done. It must not retain an emitted
	// observation's maps or slices for later modification.
	Run(ctx context.Context, emit func(model.SourceObservation))
	// Collects reports whether the reader's collection covers reference.
	Collects(reference model.Reference) bool
}

// Registration describes the reader a source should run.
type Registration struct {
	// Instance identifies the documents the source serves. Its UID registers
	// the PolicySource.
	Instance model.SourceInstance
	// Digest identifies the reader's credential and collection. Changing
	// it replaces the reader.
	Digest string
	// Settings select how Snapshot presents the source. Changing them never
	// replaces the reader.
	Settings Settings
}

// Settings are the PolicySource's choices about its documents' use, as opposed
// to how they're read.
type Settings struct {
	// Contribution selects whether Snapshot includes the source.
	Contribution api.Contribution
	// AllowedBuiltins are the builtins the source's conditions may call, nil when
	// it doesn't allow Rego conditions. Snapshot sets them on the source's
	// complete observation.
	AllowedBuiltins *model.BuiltinSet
}

// Health is a source's acquisition state.
type Health struct {
	// Complete reports that the latest acquisition admitted a complete view.
	Complete bool
	// Reason and Message explain an incomplete acquisition.
	Reason  string
	Message string
	// LastAdmitted is when a complete view last changed the source's documents
	// or ended a period of incomplete acquisition.
	LastAdmitted time.Time
}

var errStopped = errors.New("source registry is stopped")

type registryState int

const (
	registryIdle registryState = iota
	registryRunning
	registryStopped
)

// runner is one reader's run. Its fields are guarded by Registry.mu.
type runner struct {
	key     model.SourceKey
	reader  Reader
	cancel  context.CancelFunc
	stopped bool
	done    chan struct{}
	finish  func()
}

func newRunner(key model.SourceKey, reader Reader) *runner {
	done := make(chan struct{})
	return &runner{key: key, reader: reader, done: done, finish: sync.OnceFunc(func() { close(done) })}
}

type entry struct {
	// uid is the registered PolicySource UID, empty until Apply or Pause.
	uid         string
	settings    Settings
	digest      string
	runner      *runner
	paused      bool
	credential  error
	view        model.SourceObservation
	acquisition Health
}

func (e *entry) health() Health {
	health := e.acquisition
	switch {
	case e.paused:
		health.Complete, health.Reason, health.Message = false, api.ReasonPaused, "source synchronization is Paused"
	case e.credential != nil:
		health.Complete, health.Reason, health.Message = false, api.ReasonInvalidCredential, e.credential.Error()
	}
	return health
}

// observable is what subscribers learn of a source besides its documents.
// Its settings are a digest, which keeps it comparable.
type observable struct {
	uid      string
	settings string
	health   Health
}

func (e *entry) observable() observable {
	return observable{uid: e.uid, settings: model.Digest(e.settings), health: e.health()}
}

// discard replaces the view with an empty one for instance and reports
// whether that changed the documents.
func (e *entry) discard(instance model.SourceInstance) bool {
	changed := e.view.Complete || len(e.view.Documents) != 0
	e.view = model.SourceObservation{Instance: instance}
	e.acquisition = pending()
	return changed
}

// narrow keeps the documents of a complete view that collects covers
// and reports whether that changed the documents.
func (e *entry) narrow(collects func(model.Reference) bool) bool {
	if !e.view.Complete {
		return false
	}
	documents := make(map[model.Reference]model.DocumentState, len(e.view.Documents))
	for reference, state := range e.view.Documents {
		if collects(reference) {
			documents[reference] = state
		}
	}
	changed := len(documents) != len(e.view.Documents)
	e.view.Documents = documents
	return changed
}

// failing reports whether acquisition failed, rather than completing or waiting
// for its first complete observation.
func (h Health) failing() bool {
	return !h.Complete && h.Reason != api.ReasonPending
}

func pending() Health {
	return Health{Reason: api.ReasonPending, Message: "waiting for the first complete observation"}
}

// Registry holds each source's effective view and runs its reader. It's
// a manager runnable on every replica: readers start when Start runs, and stop
// when its context ends.
type Registry struct {
	// lifecycle serializes Apply, Restore, Pause and Remove.
	lifecycle sync.Mutex
	mu        sync.Mutex
	state     registryState
	sources   map[model.SourceKey]*entry
	launch    chan *runner
	stopped   chan struct{}

	subscribersMu sync.RWMutex
	subscribers   []func(model.SourceKey)
}

// NewRegistry returns a registry with no sources.
func NewRegistry() *Registry {
	return &Registry{sources: map[model.SourceKey]*entry{}, launch: make(chan *runner), stopped: make(chan struct{})}
}

// NeedLeaderElection reports that every replica runs its readers.
func (r *Registry) NeedLeaderElection() bool {
	return false
}

// Start runs readers until ctx ends, then stops them and waits for them to exit.
func (r *Registry) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.state != registryIdle {
		r.mu.Unlock()
		return errors.New("source registry was already started")
	}
	r.state = registryRunning
	var initial []*runner
	for _, source := range r.sources {
		if source.runner != nil {
			initial = append(initial, source.runner)
		}
	}
	r.mu.Unlock()
	var readers sync.WaitGroup
	for _, run := range initial {
		r.run(ctx, &readers, run)
	}
	for {
		select {
		case run := <-r.launch:
			r.run(ctx, &readers, run)
		case <-ctx.Done():
			r.mu.Lock()
			r.state = registryStopped
			r.mu.Unlock()
			close(r.stopped)
			readers.Wait()
			return nil
		}
	}
}

func (r *Registry) run(ctx context.Context, readers *sync.WaitGroup, run *runner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if run.stopped {
		run.finish()
		return
	}
	runContext, cancel := context.WithCancel(ctx)
	run.cancel = cancel
	readers.Go(func() {
		defer run.finish()
		defer cancel()
		run.reader.Run(runContext, func(observation model.SourceObservation) { r.accept(run, observation) })
	})
}

// Subscribe registers fn for the key of every source whose registered UID,
// settings, health or documents change. fn must not block for long. Earlier
// changes aren't replayed.
func (r *Registry) Subscribe(fn func(model.SourceKey)) {
	r.subscribersMu.Lock()
	defer r.subscribersMu.Unlock()
	r.subscribers = append(r.subscribers, fn)
}

func (r *Registry) notify(key model.SourceKey) {
	r.subscribersMu.RLock()
	defer r.subscribersMu.RUnlock()
	for _, fn := range r.subscribers {
		fn(key)
	}
}

// Apply registers the source's PolicySource UID and runs the reader reg
// describes. It records the UID before calling build: a changed UID stops
// the running reader and discards a view not restored for the new UID, whatever
// build returns. It does nothing more when that reader is already running.
// Otherwise it calls build. A build error is recorded as an InvalidCredential
// health issue, keeps any reader of the same UID running and leaves the origin
// unchanged. A built reader replaces the running one: a changed origin discards
// the view, and otherwise the view is narrowed to the new reader's collection
// and served until its first complete observation.
func (r *Registry) Apply(reg Registration, build func() (Reader, error)) error {
	key := reg.Instance.Key
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	r.mu.Lock()
	if r.state == registryStopped {
		r.mu.Unlock()
		return errStopped
	}
	source := r.entryLocked(key)
	before := source.observable()
	unregistered, changed := r.registerLocked(source, key, reg.Instance.UID, reg.Settings)
	defer wait(unregistered)
	source.paused = false
	if source.runner != nil && source.digest == reg.Digest && source.view.Instance == reg.Instance {
		source.credential = nil
		r.settleLocked(key, source, before, changed)
		return nil
	}
	r.mu.Unlock()

	reader, err := build()
	r.mu.Lock()
	if err != nil {
		source.credential = err
		r.settleLocked(key, source, before, changed)
		return nil
	}
	var replaced <-chan struct{}
	if source.runner != nil {
		replaced = r.stopLocked(source.runner)
		source.runner = nil
	}
	r.mu.Unlock()
	wait(replaced)

	r.mu.Lock()
	if source.view.Instance != reg.Instance {
		changed = source.discard(reg.Instance) || changed
	} else {
		changed = source.narrow(reader.Collects) || changed
	}
	source.digest, source.credential = reg.Digest, nil
	run := newRunner(key, reader)
	source.runner = run
	launch := r.state == registryRunning
	r.settleLocked(key, source, before, changed)
	if launch {
		select {
		case r.launch <- run:
		case <-r.stopped:
			run.finish()
		}
	}
	return nil
}

// Restore seeds a source's view from the persistent cache. It's accepted only
// while the registry has no complete view for the source, and doesn't register
// the source.
func (r *Registry) Restore(view model.SourceObservation) {
	key := view.Instance.Key
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	r.mu.Lock()
	if source, found := r.sources[key]; found && source.view.Complete {
		r.mu.Unlock()
		return
	}
	source := r.entryLocked(key)
	before := source.observable()
	view.Complete = true
	source.view = view
	r.settleLocked(key, source, before, true)
}

// Pause registers the source's PolicySource UID and stops its reader
// for synchronization Paused. A changed UID discards the view; otherwise
// the view is narrowed by collects and kept. settings apply as they do
// for Apply. Pause never changes the view's origin.
func (r *Registry) Pause(key model.SourceKey, uid string, settings Settings, collects func(model.Reference) bool) {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	r.mu.Lock()
	source := r.entryLocked(key)
	before := source.observable()
	unregistered, changed := r.registerLocked(source, key, uid, settings)
	defer wait(unregistered)
	var stopped <-chan struct{}
	if source.runner != nil {
		stopped = r.stopLocked(source.runner)
		source.runner = nil
	}
	defer wait(stopped)
	source.paused, source.credential, source.digest = true, nil, ""
	changed = source.narrow(collects) || changed
	r.settleLocked(key, source, before, changed)
}

// registerLocked records uid and settings. A UID other than the one registered
// stops the source's reader, and returns a channel closed once it has exited;
// a UID other than the view's discards the view, keeping a view restored
// for uid. It reports whether the documents changed.
func (r *Registry) registerLocked(source *entry, key model.SourceKey, uid string, settings Settings) (<-chan struct{}, bool) {
	source.settings = settings
	if source.uid == uid {
		return nil, false
	}
	source.uid = uid
	var stopped <-chan struct{}
	if source.runner != nil {
		stopped = r.stopLocked(source.runner)
		source.runner = nil
	}
	source.digest, source.credential = "", nil
	if source.view.Instance.UID == uid {
		return stopped, false
	}
	return stopped, source.discard(model.SourceInstance{Key: key, UID: uid})
}

// Remove stops a source's reader and discards its view. It's only for a deleted
// PolicySource.
func (r *Registry) Remove(key model.SourceKey) {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	r.mu.Lock()
	source, found := r.sources[key]
	if !found {
		r.mu.Unlock()
		return
	}
	delete(r.sources, key)
	var previous <-chan struct{}
	if source.runner != nil {
		previous = r.stopLocked(source.runner)
	}
	forgetMetrics(key)
	r.mu.Unlock()
	wait(previous)
	r.notify(key)
}

// Registered returns the PolicySource UID the source is registered under,
// and whether it's registered.
func (r *Registry) Registered(key model.SourceKey) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	source, found := r.sources[key]
	if !found || source.uid == "" {
		return "", false
	}
	return source.uid, true
}

// Snapshot returns the effective views of the registered sources. An Inert
// source, and one without a complete view, is an incomplete observation whose
// Failure carries only the reason: the message changes as acquisition retries,
// and Health reports it. A complete view carries the source's allowed builtins.
// The map is the caller's; the observations are shared and immutable.
func (r *Registry) Snapshot() map[model.SourceKey]model.SourceObservation {
	r.mu.Lock()
	defer r.mu.Unlock()
	snapshot := make(map[model.SourceKey]model.SourceObservation, len(r.sources))
	for key, source := range r.sources {
		switch {
		case source.uid == "":
		case source.settings.Contribution == api.ContributionInert:
			snapshot[key] = model.SourceObservation{Instance: source.view.Instance, Failure: model.Failure{Reason: string(api.ContributionInert)}}
		case !source.view.Complete:
			snapshot[key] = model.SourceObservation{Instance: source.view.Instance, Failure: model.Failure{Reason: source.health().Reason}}
		default:
			view := source.view
			view.AllowedBuiltins = source.settings.AllowedBuiltins
			snapshot[key] = view
		}
	}
	return snapshot
}

// Effective returns one source's view, whatever its settings. An unknown
// source's view, like any incomplete one, has no documents.
func (r *Registry) Effective(key model.SourceKey) model.SourceObservation {
	r.mu.Lock()
	defer r.mu.Unlock()
	if source, found := r.sources[key]; found {
		return source.view
	}
	return model.SourceObservation{}
}

// Health returns one source's acquisition state, which is pending
// for an unknown source.
func (r *Registry) Health(key model.SourceKey) Health {
	r.mu.Lock()
	defer r.mu.Unlock()
	if source, found := r.sources[key]; found {
		return source.health()
	}
	return pending()
}

func (r *Registry) entryLocked(key model.SourceKey) *entry {
	source, found := r.sources[key]
	if !found {
		source = &entry{view: model.SourceObservation{}, acquisition: pending()}
		r.sources[key] = source
	}
	return source
}

// settleLocked releases r.mu and notifies subscribers when the source's
// documents changed or it no longer matches before.
func (r *Registry) settleLocked(key model.SourceKey, source *entry, before observable, changed bool) {
	after := source.observable()
	changed = changed || after != before
	if changed {
		observeHealth(key, after.health)
	}
	r.mu.Unlock()
	if changed {
		r.notify(key)
	}
}

// wait waits for stopped to close, if it's set.
func wait(stopped <-chan struct{}) {
	if stopped != nil {
		<-stopped
	}
}

// stopLocked stops run and returns a channel closed once it has exited.
func (r *Registry) stopLocked(run *runner) <-chan struct{} {
	run.stopped = true
	switch {
	case run.cancel != nil:
		run.cancel()
	case r.state == registryIdle:
		run.finish()
	}
	return run.done
}

func (r *Registry) accept(run *runner, observation model.SourceObservation) {
	r.mu.Lock()
	source, found := r.sources[run.key]
	if !found || source.runner != run || run.stopped {
		r.mu.Unlock()
		return
	}
	before := source.observable()
	changed := false
	if observation.Complete {
		// A view whose documents are semantically unchanged is kept, so metadata-only
		// updates neither notify nor rewrite the cache.
		changed = !source.view.Complete || !sameDocuments(source.view.Documents, observation.Documents)
		if changed {
			source.view = observation
		}
		if changed || !source.acquisition.Complete {
			source.acquisition = Health{Complete: true, LastAdmitted: time.Now()}
		}
	} else {
		acquisition := Health{Reason: observation.Failure.Reason, Message: observation.Failure.Message, LastAdmitted: source.acquisition.LastAdmitted}
		if !source.acquisition.failing() {
			countFailure(run.key)
		}
		source.acquisition = acquisition
	}
	r.settleLocked(run.key, source, before, changed)
}

// sameDocuments compares documents by their semantic digests.
func sameDocuments(previous, current map[model.Reference]model.DocumentState) bool {
	if len(previous) != len(current) {
		return false
	}
	for reference, state := range current {
		earlier, found := previous[reference]
		if !found || earlier.UID != state.UID || earlier.Digest != state.Digest {
			return false
		}
	}
	return true
}
