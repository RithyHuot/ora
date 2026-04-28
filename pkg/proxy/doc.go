// Package proxy implements the loopback HTTPS-CONNECT egress proxy that
// gates outbound network access from the sandboxed CLI. ora wires
// HTTPS_PROXY=http://127.0.0.1:<port> into the wrapped child's environment
// and runs Egress on that port; the child can connect only to allowlisted
// hosts on port 443.
//
// External callers typically use ValidateAllowedDomain(s) to canonicalize
// allowlist entries before constructing an Egress. The Egress type, the
// ParentProxy type, and ResolveParentProxy are part of the stable public
// API; the host matcher (compileMatcher / hostMatcher) is intentionally
// unexported and consumed only via Egress.Allowed.
//
// Stability: this package is part of ora's public API. Exported symbols
// are stable within a major version.
package proxy
