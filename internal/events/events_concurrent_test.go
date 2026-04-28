package events

import (
	"bufio"
	"bytes"
	"encoding/json"
	"sync"
	"testing"
)

// syncWriter serializes writes so the buffer never sees torn writes from
// the test harness's perspective; this isolates "did Emitter properly hold
// its mutex?" from "is bytes.Buffer concurrent-safe?" (it is not).
type syncWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func TestEmitter_ConcurrentEmissionsDoNotTear(t *testing.T) {
	const goroutines = 50
	const perGoroutine = 20
	buf := &bytes.Buffer{}
	e := NewEmitter(&syncWriter{w: buf})

	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perGoroutine {
				e.NetworkBlocked("api.example.com", 443, "not_allowlisted")
				e.FsDeny("file-read", "/Users/x/.ssh/id_rsa")
			}
		}()
	}
	wg.Wait()

	want := goroutines * perGoroutine * 2
	got := 0
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		var m map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &m); err != nil {
			t.Fatalf("torn or malformed JSON line: %q (%v)", scanner.Text(), err)
		}
		got++
	}
	if got != want {
		t.Errorf("got %d events, want %d", got, want)
	}
}
