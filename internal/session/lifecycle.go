package session

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// StaleProfileMaxAge bounds how old a leftover profile file can be before
// the next session.New() considers it abandoned and removes it. Profiles
// orphaned by SIGKILL of the parent ora process are cleaned up on the
// next invocation rather than waiting for `doctor --sweep`.
const StaleProfileMaxAge = 1 * time.Hour

// Session bundles a unique ID, the on-disk profile path, and ordered
// cleanup hooks. Cleanup is idempotent and runs all hooks in LIFO order.
type Session struct {
	id          string
	profilePath string

	mu       sync.Mutex // guards cleanups + cleaning
	cleanups []func() error
	cleaning bool

	cleanupOnce sync.Once
	cleanupErr  error
}

// New initializes a session: assigns an ID and computes the profile path
// under ${TMPDIR}. As a side effect, sweeps any leftover ora profile files
// older than StaleProfileMaxAge to defend against SIGKILL leaks.
func New() *Session {
	id := NewID()
	if rand.IntN(100) == 0 { //nolint:gosec // non-crypto PRNG is fine for probabilistic sweep throttle
		go sweepStaleProfiles(os.TempDir(), StaleProfileMaxAge)
	}
	return &Session{
		id:          id,
		profilePath: filepath.Join(os.TempDir(), fmt.Sprintf("ora-sandbox-%s.sb", id)),
	}
}

// ListStaleProfiles returns absolute paths of leftover ora profile files
// in dir that are older than maxAge. Used by both `ora doctor` (to display)
// and the per-session sweep (to remove); having one predicate keeps the
// two consumers from drifting.
func ListStaleProfiles(dir string, maxAge time.Duration) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	cutoff := time.Now().Add(-maxAge)
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "ora-sandbox-") || !strings.HasSuffix(name, ".sb") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			out = append(out, filepath.Join(dir, name))
		}
	}
	return out
}

// sweepStaleProfiles removes ora-sandbox-*.sb files older than maxAge.
// Errors are ignored: this is best-effort hygiene, not a correctness path.
func sweepStaleProfiles(dir string, maxAge time.Duration) {
	for _, p := range ListStaleProfiles(dir, maxAge) {
		_ = os.Remove(p)
	}
}

// ID returns the session ULID.
func (s *Session) ID() string { return s.id }

// ProfilePath returns the absolute path the profile will be written to.
func (s *Session) ProfilePath() string { return s.profilePath }

// WriteProfile writes the Seatbelt profile content to ProfilePath with
// mode 0600 (only the user can read).
func (s *Session) WriteProfile(content string) error {
	return os.WriteFile(s.profilePath, []byte(content), 0o600)
}

// OnCleanup registers a hook to run during Cleanup. Hooks run in LIFO
// order so resources started last are torn down first. Safe for concurrent
// use; calling OnCleanup AFTER Cleanup has started logs a warning and
// drops the hook (a programming error: lifecycle hooks should always be
// registered before triggering cleanup).
func (s *Session) OnCleanup(fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleaning {
		slog.Warn("session: OnCleanup called after Cleanup started; hook dropped")
		return
	}
	s.cleanups = append(s.cleanups, fn)
}

// Cleanup runs all registered hooks in LIFO order, then deletes the profile
// file. Safe to call concurrently — only the first invocation across all
// goroutines runs the hooks; subsequent calls return the same aggregated
// error.
func (s *Session) Cleanup() error {
	s.cleanupOnce.Do(func() {
		s.mu.Lock()
		s.cleaning = true
		hooks := s.cleanups
		s.cleanups = nil
		s.mu.Unlock()

		var errs []error
		for i := len(hooks) - 1; i >= 0; i-- {
			if err := hooks[i](); err != nil {
				errs = append(errs, err)
			}
		}
		if err := os.Remove(s.profilePath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
		s.cleanupErr = errors.Join(errs...)
	})
	return s.cleanupErr
}
