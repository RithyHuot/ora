package denials_test

import (
	"context"
	"sync"
	"testing"

	idenials "github.com/rithyhuot/ora/internal/denials"
	pubd "github.com/rithyhuot/ora/pkg/denials"
)

func TestMulti_FansOutToAllSinks(t *testing.T) {
	var a, b idenials.Counter
	m := idenials.Multi{&a, &b}
	m.Push(context.Background(), pubd.Event{Kind: pubd.KindNetwork})
	m.Push(context.Background(), pubd.Event{Kind: pubd.KindFs})
	if a.Count(pubd.KindNetwork) != 1 || b.Count(pubd.KindNetwork) != 1 {
		t.Errorf("KindNetwork not fanned out: a=%d b=%d", a.Count(pubd.KindNetwork), b.Count(pubd.KindNetwork))
	}
	if a.Count(pubd.KindFs) != 1 || b.Count(pubd.KindFs) != 1 {
		t.Errorf("KindFs not fanned out: a=%d b=%d", a.Count(pubd.KindFs), b.Count(pubd.KindFs))
	}
}

func TestMulti_SkipsNilSinks(t *testing.T) {
	var c idenials.Counter
	m := idenials.Multi{nil, &c, nil}
	m.Push(context.Background(), pubd.Event{Kind: pubd.KindFs})
	if got := c.Count(pubd.KindFs); got != 1 {
		t.Errorf("nil sink in Multi should not block delivery; got count=%d, want 1", got)
	}
}

func TestMulti_NilOnlySliceDoesNotPanic(t *testing.T) {
	// Multi's documented contract is to skip nil entries; a slice of only
	// nils must not panic.
	m := idenials.Multi{nil, nil, nil}
	m.Push(context.Background(), pubd.Event{Kind: pubd.KindNetwork})
}

func TestCounter_ZeroValueUsable(t *testing.T) {
	var c idenials.Counter
	c.Push(context.Background(), pubd.Event{Kind: pubd.KindNetwork})
	if got := c.Count(pubd.KindNetwork); got != 1 {
		t.Errorf("zero-value Counter: got %d, want 1", got)
	}
}

func TestCounter_TalliesPerKind(t *testing.T) {
	var c idenials.Counter
	c.Push(context.Background(), pubd.Event{Kind: pubd.KindNetwork})
	c.Push(context.Background(), pubd.Event{Kind: pubd.KindNetwork})
	c.Push(context.Background(), pubd.Event{Kind: pubd.KindFs})
	if got := c.Count(pubd.KindNetwork); got != 2 {
		t.Errorf("KindNetwork: got %d, want 2", got)
	}
	if got := c.Count(pubd.KindFs); got != 1 {
		t.Errorf("KindFs: got %d, want 1", got)
	}
	if got := c.Count(pubd.KindStderrSignature); got != 0 {
		t.Errorf("KindStderrSignature: got %d, want 0", got)
	}
}

func TestCounter_GoroutineSafe(t *testing.T) {
	var c idenials.Counter
	var wg sync.WaitGroup
	wg.Add(50)
	for range 50 {
		go func() {
			defer wg.Done()
			c.Push(context.Background(), pubd.Event{Kind: pubd.KindNetwork})
		}()
	}
	wg.Wait()
	if got := c.Count(pubd.KindNetwork); got != 50 {
		t.Errorf("Counter dropped events under concurrency: got %d, want 50", got)
	}
}
