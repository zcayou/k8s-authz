package utils

import (
	"context"
	"encoding/json"
	"slices"
	"sync"

	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/engineclient"
	"github.com/zcayou/k8s-authz/internal/model"
)

// The writes FakeEngines records.
const (
	WriteConditions = "conditions"
	WriteState      = "state"
)

// FakeEngines stands in for the engines' management API, keyed by engine
// address. It serves the state and the conditions module digest last installed
// at each address, fails the addresses a spec selects, and records every target
// it's asked about and every write it accepts.
type FakeEngines struct {
	mutex             sync.Mutex
	states            map[string][]byte
	modules           map[string]string
	failures          map[string]error
	conditionFailures map[string]error
	targets           []engineclient.Target
	writes            map[string][]string
}

// NewFakeEngines returns engines that hold no state and no conditions module.
func NewFakeEngines() *FakeEngines {
	return &FakeEngines{
		states: map[string][]byte{}, modules: map[string]string{},
		failures: map[string]error{}, conditionFailures: map[string]error{},
		writes: map[string][]string{},
	}
}

// Installed returns the revision of the state and the digest of the conditions
// module installed at target's address.
func (f *FakeEngines) Installed(ctx context.Context, target engineclient.Target) (engineclient.Installed, error) {
	state, err := f.contact(ctx, target)
	if err != nil {
		return engineclient.Installed{}, err
	}
	installed := engineclient.Installed{ConditionsDigest: f.Module(target.Address)}
	if state == nil {
		return installed, nil
	}
	var content model.ContentRevision
	if err := json.Unmarshal(state, &content); err != nil {
		return engineclient.Installed{}, err
	}
	installed.Revision = content.Revision
	return installed, nil
}

// Replace installs state at target's address.
func (f *FakeEngines) Replace(ctx context.Context, target engineclient.Target, state []byte) error {
	if _, err := f.contact(ctx, target); err != nil {
		return err
	}
	f.Install(target.Address, state)
	f.record(target.Address, WriteState)
	return nil
}

// PutConditions installs module's digest at target's address.
func (f *FakeEngines) PutConditions(ctx context.Context, target engineclient.Target, module condition.Module) error {
	if _, err := f.contact(ctx, target); err != nil {
		return err
	}
	f.mutex.Lock()
	err := f.conditionFailures[target.Address]
	f.mutex.Unlock()
	if err != nil {
		return err
	}
	f.InstallModule(target.Address, module.Digest)
	f.record(target.Address, WriteConditions)
	return nil
}

func (f *FakeEngines) record(address, write string) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.writes[address] = append(f.writes[address], write)
}

// Snapshot returns the state installed at target's address, or nil.
func (f *FakeEngines) Snapshot(ctx context.Context, target engineclient.Target) (json.RawMessage, error) {
	return f.contact(ctx, target)
}

func (f *FakeEngines) contact(ctx context.Context, target engineclient.Target) ([]byte, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.targets = append(f.targets, target)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := f.failures[target.Address]; err != nil {
		return nil, err
	}
	return f.states[target.Address], nil
}

// Install sets the state address serves; nil removes it.
func (f *FakeEngines) Install(address string, state []byte) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if state == nil {
		delete(f.states, address)
		return
	}
	f.states[address] = slices.Clone(state)
}

// InstallModule sets the digest of the conditions module address serves; ""
// removes it.
func (f *FakeEngines) InstallModule(address, digest string) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if digest == "" {
		delete(f.modules, address)
		return
	}
	f.modules[address] = digest
}

// Module returns the digest of the conditions module address serves, or "".
func (f *FakeEngines) Module(address string) string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.modules[address]
}

// Writes returns the writes address accepted, in order.
func (f *FakeEngines) Writes(address string) []string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return slices.Clone(f.writes[address])
}

// State returns the state address serves, or nil.
func (f *FakeEngines) State(address string) []byte {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return slices.Clone(f.states[address])
}

// Fail makes every request to address fail with err; nil restores it.
func (f *FakeEngines) Fail(address string, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if err == nil {
		delete(f.failures, address)
		return
	}
	f.failures[address] = err
}

// FailConditions makes only conditions module writes to address fail with err;
// nil restores them.
func (f *FakeEngines) FailConditions(address string, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if err == nil {
		delete(f.conditionFailures, address)
		return
	}
	f.conditionFailures[address] = err
}

// Targets returns every target the engines were asked about, in order.
func (f *FakeEngines) Targets() []engineclient.Target {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return slices.Clone(f.targets)
}

// FakeReader is a source reader a spec drives. Once it runs, it hands
// the spec its emit function through Emitters, and it runs until its context
// ends.
type FakeReader struct {
	collects func(model.Reference) bool
	emitters chan func(model.SourceObservation)
	stopped  chan struct{}
}

// NewFakeReader returns a reader whose collection is what collects reports,
// or everything when collects is nil.
func NewFakeReader(collects func(model.Reference) bool) *FakeReader {
	return &FakeReader{collects: collects, emitters: make(chan func(model.SourceObservation), 1), stopped: make(chan struct{})}
}

// Run hands emit to the spec and waits for ctx to end.
func (r *FakeReader) Run(ctx context.Context, emit func(model.SourceObservation)) {
	defer close(r.stopped)
	r.emitters <- emit
	<-ctx.Done()
}

// Collects reports whether the reader's collection covers reference.
func (r *FakeReader) Collects(reference model.Reference) bool {
	return r.collects == nil || r.collects(reference)
}

// Emitters delivers the reader's emit function once it runs.
func (r *FakeReader) Emitters() <-chan func(model.SourceObservation) {
	return r.emitters
}

// Stopped is closed once Run has returned.
func (r *FakeReader) Stopped() <-chan struct{} {
	return r.stopped
}
