package session

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSweepStaleProfiles_RemovesOldOraProfilesOnly(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "ora-sandbox-OLD.sb")
	young := filepath.Join(dir, "ora-sandbox-YOUNG.sb")
	stranger := filepath.Join(dir, "not-mine-OLD.sb")
	for _, p := range []string{old, young, stranger} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(old, twoHoursAgo, twoHoursAgo); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(stranger, twoHoursAgo, twoHoursAgo); err != nil {
		t.Fatal(err)
	}

	sweepStaleProfiles(dir, 1*time.Hour)

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("old ora profile should be removed; stat err = %v", err)
	}
	if _, err := os.Stat(young); err != nil {
		t.Errorf("young profile must remain; stat err = %v", err)
	}
	if _, err := os.Stat(stranger); err != nil {
		t.Errorf("non-ora file must not be touched; stat err = %v", err)
	}
}

func TestNewID_FormatAndUniqueness(t *testing.T) {
	a := NewID()
	b := NewID()
	if len(a) != 26 {
		t.Errorf("expected 26-char ULID, got %d (%s)", len(a), a)
	}
	if a == b {
		t.Error("expected unique IDs")
	}
}

func TestNewID_MonotonicUnderBurst(t *testing.T) {
	const n = 1000
	ids := make([]string, n)
	for i := range ids {
		ids[i] = NewID()
	}
	for i := 1; i < n; i++ {
		if ids[i] <= ids[i-1] {
			t.Fatalf("NewID must be monotonic; ids[%d]=%s <= ids[%d]=%s", i, ids[i], i-1, ids[i-1])
		}
	}
}

func TestSession_WriteAndCleanupProfile(t *testing.T) {
	sess := New()
	defer func() {
		if err := sess.Cleanup(); err != nil {
			t.Errorf("deferred Cleanup: %v", err)
		}
	}()
	if !strings.HasPrefix(filepath.Base(sess.ProfilePath()), "ora-sandbox-") {
		t.Errorf("ProfilePath should be ora-sandbox-*.sb, got %s", sess.ProfilePath())
	}

	if err := sess.WriteProfile("(version 1)\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sess.ProfilePath()); err != nil {
		t.Errorf("expected profile written: %v", err)
	}
	if err := sess.Cleanup(); err != nil {
		t.Errorf("Cleanup: %v", err)
	}
	if _, err := os.Stat(sess.ProfilePath()); !os.IsNotExist(err) {
		t.Errorf("expected profile deleted after Cleanup, stat err: %v", err)
	}
}

func TestSession_OnCleanupRunsAllInReverseOrder(t *testing.T) {
	sess := New()
	var calls []int
	sess.OnCleanup(func() error { calls = append(calls, 1); return nil })
	sess.OnCleanup(func() error { calls = append(calls, 2); return nil })
	sess.OnCleanup(func() error { calls = append(calls, 3); return nil })
	if err := sess.Cleanup(); err != nil {
		t.Errorf("Cleanup: %v", err)
	}
	want := []int{3, 2, 1}
	for i := range want {
		if calls[i] != want[i] {
			t.Errorf("cleanup order: got %v, want %v", calls, want)
			return
		}
	}
}

func TestSession_CleanupConcurrentSafety(t *testing.T) {
	s := New()
	var hookCount int32
	s.OnCleanup(func() error {
		atomic.AddInt32(&hookCount, 1)
		return nil
	})

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Cleanup()
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&hookCount); got != 1 {
		t.Errorf("expected hook to run exactly once across 10 concurrent Cleanup calls; got %d", got)
	}
}

func TestSession_OnCleanupRaceFree(t *testing.T) {
	t.Parallel()
	s := New()
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.OnCleanup(func() error { return nil })
		}()
	}
	// Race: half the goroutines register, the others trigger cleanup.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = s.Cleanup()
	}()
	wg.Wait()
	// Idempotency check: a second Cleanup must not panic.
	_ = s.Cleanup()
}
