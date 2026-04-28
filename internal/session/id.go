// Package session manages per-invocation lifecycle: a unique session ID,
// the profile file path, and ordered cleanup hooks.
package session

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

var (
	entropyMu sync.Mutex
	entropy   = ulid.Monotonic(rand.Reader, 0)
)

// NewID returns a fresh ULID string (26 characters, sortable, no central
// coordination required). IDs generated in tight loops within the same
// millisecond are guaranteed to be monotonically increasing — the JSON
// event stream relies on this for ordering semantics.
func NewID() string {
	entropyMu.Lock()
	defer entropyMu.Unlock()
	return ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String()
}
