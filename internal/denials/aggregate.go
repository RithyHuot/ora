// Package denials hosts ora-internal aggregations over the public
// pkg/denials.Sink interface. Multi fans events out to multiple sinks;
// Counter tallies events by Kind. Both are zero-value usable.
package denials

import (
	"context"
	"sync"

	pubd "github.com/rithyhuot/ora/pkg/denials"
)

// Multi fans an Event out to every non-nil Sink. Push is concurrent-safe
// iff all constituent sinks are. Nil entries are skipped so callers can
// build a Multi from optional sinks without filtering first.
type Multi []pubd.Sink

// Push implements pubd.Sink. Nil entries in the slice are skipped. The
// context is threaded to every constituent sink so cancellation propagates.
func (m Multi) Push(ctx context.Context, e pubd.Event) {
	for _, s := range m {
		if s != nil {
			s.Push(ctx, e)
		}
	}
}

// Counter is a Sink that counts events by Kind. The zero value is usable;
// the internal map is lazily initialized on first Push or Count.
// Goroutine-safe.
type Counter struct {
	mu     sync.Mutex
	counts map[pubd.Kind]int
}

// Push implements pubd.Sink. Counter is an in-memory tally and does not
// block, so the context is ignored.
func (c *Counter) Push(_ context.Context, e pubd.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts == nil {
		c.counts = make(map[pubd.Kind]int)
	}
	c.counts[e.Kind]++
}

// Count returns the number of events of the given kind seen so far.
func (c *Counter) Count(k pubd.Kind) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[k]
}
