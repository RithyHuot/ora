// Package denials defines the single event taxonomy used by every source
// of sandbox denial signals (egress proxy, kernel log monitor, child-stderr
// classifier) and the Sink interface those events flow through.
//
// Adding a new producer or consumer means implementing this interface in
// one place rather than coordinating four (proxy, sandbox, events, cli).
//
// Aggregation helpers (Multi, Counter) live in internal/denials for ora's
// own use and are not part of the public API.
//
// Stability: this package is part of ora's public API. Exported symbols
// are stable within a major version.
package denials
