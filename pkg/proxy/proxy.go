package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rithyhuot/ora/pkg/denials"
)

// DefaultMaxConcurrentTunnels caps the number of in-flight CONNECT tunnels
// when Egress.MaxConcurrentTunnels is zero. A sandboxed CLI cannot exhaust
// host file descriptors or memory by spawning unbounded CONNECT requests
// once this is hit; further requests get a 503.
const DefaultMaxConcurrentTunnels = 64

// DefaultTunnelIdleTimeout bounds how long either direction of a CONNECT
// tunnel can sit idle when Egress.TunnelIdleTimeout is zero.
const DefaultTunnelIdleTimeout = 10 * time.Minute

// DefaultShutdownTimeout is the per-phase wait used by Stop when
// Egress.ShutdownTimeout is zero. Stop applies it twice (drain → force-close
// → drain), so end-to-end Stop is bounded by 2*DefaultShutdownTimeout.
const DefaultShutdownTimeout = 2 * time.Second

// EgressConfig is the immutable configuration used by NewEgress.
type EgressConfig struct {
	Allowed              []string
	Logger               *slog.Logger
	Parent               *ParentProxy
	Denials              denials.Sink
	MaxConcurrentTunnels int
	TunnelIdleTimeout    time.Duration
	ShutdownTimeout      time.Duration
}

// NewEgress constructs an Egress from immutable config. The caller's Allowed
// slice is defensively copied so later mutation has no effect on the proxy.
func NewEgress(cfg EgressConfig) *Egress {
	return &Egress{
		Allowed:              append([]string(nil), cfg.Allowed...),
		Logger:               cfg.Logger,
		Parent:               cfg.Parent,
		Denials:              cfg.Denials,
		MaxConcurrentTunnels: cfg.MaxConcurrentTunnels,
		TunnelIdleTimeout:    cfg.TunnelIdleTimeout,
		ShutdownTimeout:      cfg.ShutdownTimeout,
	}
}

// Egress is an in-process HTTPS-CONNECT proxy. It listens on 127.0.0.1 on a
// kernel-assigned port and accepts only CONNECT host:443 from a domain
// allowlist; all other methods, ports, and hosts return 403. Plain HTTP is
// rejected by construction (the Server's request handler returns 403 for
// non-CONNECT methods).
//
// Construct via NewEgress(EgressConfig{...}). Bare struct-literal construction
// (`&Egress{...}`) still compiles for back-compat with existing callers, but
// post-Start mutation of config fields is undefined.
type Egress struct {
	// Allowed is the host allowlist read once at Start; later mutations have
	// no effect on the running matcher. An empty or nil Allowed blocks every
	// CONNECT request — there is no opt-in to allow-all, by design. To
	// permit traffic to a host, list it (or a wildcard like "*.example.com")
	// explicitly.
	Allowed []string
	// Logger is snapshotted at Start; later mutation has no effect.
	Logger *slog.Logger
	// Parent proxy. Snapshotted at Start; later mutation has no effect.
	Parent *ParentProxy
	// Denials receives every block (non-443 port, non-allowlisted host,
	// concurrent-cap exhaustion). Snapshotted at Start; later mutation has no
	// effect on the running proxy. nil is treated as denials.Discard.
	Denials denials.Sink

	// MaxConcurrentTunnels overrides DefaultMaxConcurrentTunnels when > 0.
	MaxConcurrentTunnels int
	// TunnelIdleTimeout overrides DefaultTunnelIdleTimeout when > 0.
	TunnelIdleTimeout time.Duration
	// ShutdownTimeout caps how long Stop waits for graceful CONNECT-tunnel
	// drain before force-closing remaining tunnels. Zero uses
	// DefaultShutdownTimeout. Stop applies this twice — once before
	// closeAllTunnels, once after — so end-to-end Stop latency is bounded
	// by 2*ShutdownTimeout in the worst case.
	ShutdownTimeout time.Duration

	// testPorts overrides the set of allowed CONNECT ports. Nil means only
	// port 443 is permitted. This field is unexported and must only be set
	// in tests — it must never be used to weaken production egress policy.
	testPorts map[string]struct{}

	networkBlocks int64 // atomic counter; read via NetworkBlocks().

	// mu guards server / listener and the started flag — Start writes both
	// and Stop reads them. The mutex is the proxy's sole serialization point
	// against concurrent Start/Stop; in practice the orchestrator calls them
	// sequentially, but the doctor's bind probe and any future timeout path
	// could race without it.
	mu       sync.Mutex
	listener net.Listener
	server   *http.Server
	started  bool

	allowed       []string // snapshot of Allowed at Start
	matcher       hostMatcher
	wg            sync.WaitGroup
	tunnels       chan struct{} // semaphore: cap = effective tunnel cap
	idleTimeout   time.Duration // resolved at Start
	activeTunnels sync.Map      // map[*net.Conn]struct{}; tracked for force-close on Stop

	// Snapshots taken at Start. Reading these on the hot path avoids racing
	// with post-Start mutation of the public fields.
	denials denials.Sink
	logger  *slog.Logger
	parent  *ParentProxy
}

// trackTunnel records the (client, upstream) pair so Stop can force-close
// them if the wg drain stalls past the timeout.
func (e *Egress) trackTunnel(client, upstream net.Conn) {
	e.activeTunnels.Store(client, upstream)
}

func (e *Egress) untrackTunnel(client net.Conn) {
	e.activeTunnels.Delete(client)
}

func (e *Egress) closeAllTunnels() {
	e.activeTunnels.Range(func(k, v any) bool {
		_ = k.(net.Conn).Close()
		_ = v.(net.Conn).Close()
		return true
	})
}

// NetworkBlocks returns the number of CONNECT requests rejected by the
// allowlist or capacity limits since this Egress was started.
func (e *Egress) NetworkBlocks() int64 {
	return atomic.LoadInt64(&e.networkBlocks)
}

func (e *Egress) effectiveTunnelCap() int {
	if e.MaxConcurrentTunnels > 0 {
		return e.MaxConcurrentTunnels
	}
	return DefaultMaxConcurrentTunnels
}

func (e *Egress) effectiveIdleTimeout() time.Duration {
	if e.TunnelIdleTimeout > 0 {
		return e.TunnelIdleTimeout
	}
	return DefaultTunnelIdleTimeout
}

func (e *Egress) effectiveShutdownTimeout() time.Duration {
	if e.ShutdownTimeout > 0 {
		return e.ShutdownTimeout
	}
	return DefaultShutdownTimeout
}

func (e *Egress) pushDeny(ctx context.Context, host string, port int, reason string) {
	if e.denials == nil {
		return
	}
	e.denials.Push(ctx, denials.Event{
		Kind:   denials.KindNetwork,
		Host:   host,
		Port:   port,
		Reason: reason,
	})
}

// Start binds 127.0.0.1:<random-free> and begins serving. Returns the
// chosen port. Caller wires HTTPS_PROXY=http://127.0.0.1:<port> into the
// sandboxed CLI's environment.
//
// ctx is honored only for the initial bind: if ctx is already cancelled,
// Start returns its error without binding. Once running, the server's
// lifetime is bound by Stop, not ctx — cancelling ctx after Start
// returns has no effect. Use Stop to shut down.
func (e *Egress) Start(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("egress: start: %w", err)
	}
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return 0, errors.New("egress: already started")
	}
	if e.Logger == nil {
		e.Logger = slog.Default()
	}
	// Snapshot allowlist so post-Start mutations don't affect the matcher.
	e.allowed = append([]string(nil), e.Allowed...)
	canonical, err := ValidateAllowedDomains(e.allowed)
	if err != nil {
		e.mu.Unlock()
		return 0, fmt.Errorf("egress: validate allowed domains: %w", err)
	}
	e.allowed = canonical
	e.matcher = compileMatcher(e.allowed)
	e.tunnels = make(chan struct{}, e.effectiveTunnelCap())
	e.idleTimeout = e.effectiveIdleTimeout()
	e.denials = e.Denials
	e.logger = e.Logger
	e.parent = e.Parent

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.mu.Unlock()
		return 0, fmt.Errorf("egress: listen: %w", err)
	}
	e.listener = ln

	// Use a plain HandlerFunc rather than http.ServeMux: the ServeMux performs
	// path cleaning and issues 301 redirects for authority-form CONNECT
	// requests (e.g. "host:443") because they lack a leading slash. A raw
	// HandlerFunc bypasses that logic entirely.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "ora egress: HTTPS CONNECT only", http.StatusForbidden)
			return
		}
		e.handleConnect(w, r)
	})

	e.server = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	srv := e.server
	logger := e.logger
	e.started = true
	e.mu.Unlock()

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("egress.server", "err", err)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// Stop performs a graceful shutdown: stops accepting new connections, waits
// for in-flight CONNECT tunnels up to ShutdownTimeout (per phase), then
// force-closes any remaining tunnels and drains the WaitGroup. The shutdown
// is rooted on context.Background() rather than a caller-supplied ctx
// because Stop typically runs on a deferred path where the caller's ctx is
// already cancelled (the child exited and ctx cancellation propagated);
// honoring that ctx would skip the graceful drain entirely. Use
// ShutdownTimeout to bound the wait.
func (e *Egress) Stop() error {
	e.mu.Lock()
	if !e.started {
		e.mu.Unlock()
		return nil
	}
	srv := e.server
	logger := e.logger
	e.mu.Unlock()

	timeout := e.effectiveShutdownTimeout()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := srv.Shutdown(shutdownCtx)
	if err != nil {
		_ = srv.Close()
	}

	// Single waiter goroutine shared across both drain phases — the previous
	// per-call waitFor leaked one goroutine on every timeout path. The waiter
	// will exit on its own once wg drains; the worst-case lifetime is bounded
	// by the upstream tunnel idle timeout, which is finite.
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()

	t1 := time.NewTimer(timeout)
	defer t1.Stop()
	select {
	case <-done:
		return err
	case <-t1.C:
	}
	e.closeAllTunnels()
	t2 := time.NewTimer(timeout)
	defer t2.Stop()
	select {
	case <-done:
		return err
	case <-t2.C:
	}
	leaked := 0
	e.activeTunnels.Range(func(_, _ any) bool { leaked++; return true })
	logger.Warn("egress.stop.tunnels_still_active",
		"leaked", leaked,
		"note", "force-closed; shared waiter will drain when goroutines return")
	return err
}

func (e *Egress) handleConnect(w http.ResponseWriter, r *http.Request) {
	// For CONNECT requests, Go's net/http populates r.Host from the
	// request-line URI (not the Host: header) and strips Host from
	// r.Header. This is the load-bearing parser invariant that makes
	// using r.Host safe here — see TestProxy_GoHTTPCollapsesConnectHostToURI
	// in proxy_test.go for the regression pin.
	host, port, err := net.SplitHostPort(r.Host)
	start := time.Now()
	if err != nil {
		e.logger.Warn("egress.connect.bad_host", "host", r.Host, "err", err)
		http.Error(w, "bad host:port", http.StatusBadRequest)
		return
	}
	// RFC 1034 canonical absolute hostname (trailing dot) is equivalent to
	// the relative form for matching purposes. The validator rejects
	// trailing-dot allowlist entries, so this normalization is one-way:
	// strip from CONNECT input, never add back.
	host = strings.TrimSuffix(host, ".")
	if !e.portAllowed(port) {
		e.logger.Warn("egress.deny", "host", host, "port", port, "reason", "non_443")
		e.pushDeny(r.Context(), host, atoi(port), "non_443")
		atomic.AddInt64(&e.networkBlocks, 1)
		http.Error(w, "ora egress: only port 443 allowed", http.StatusForbidden)
		return
	}
	if !e.matcher(host) {
		e.logger.Warn("egress.deny", "host", host, "port", port, "reason", "not_allowlisted")
		e.pushDeny(r.Context(), host, atoi(port), "not_allowlisted")
		atomic.AddInt64(&e.networkBlocks, 1)
		http.Error(w, "ora egress: host not allowlisted", http.StatusForbidden)
		return
	}

	// Cap concurrent tunnels: a buggy or malicious sandboxed CLI cannot pin
	// unbounded fds/memory by spawning CONNECTs in a tight loop.
	select {
	case e.tunnels <- struct{}{}:
	default:
		e.logger.Warn("egress.deny", "host", host, "port", port, "reason", "tunnel_cap")
		e.pushDeny(r.Context(), host, atoi(port), "tunnel_cap")
		atomic.AddInt64(&e.networkBlocks, 1)
		http.Error(w, "ora egress: too many concurrent tunnels", http.StatusServiceUnavailable)
		return
	}
	// Increment the WaitGroup *before* any blocking I/O. Server.Shutdown
	// only blocks until the request handler returns; any wg.Add that
	// happens after blocking I/O could race with Stop's wg.Wait.
	e.wg.Add(1)
	wgDone := false
	tunnelSlotReleased := false
	cleanupHandlerExit := func() {
		if !tunnelSlotReleased {
			<-e.tunnels
			tunnelSlotReleased = true
		}
		if !wgDone {
			e.wg.Done()
			wgDone = true
		}
	}

	var upstream net.Conn
	switch {
	case e.parent != nil && !e.parent.shouldBypass(host):
		upstream, err = dialViaParent(e.parent, r.Host, 10*time.Second)
	default:
		upstream, err = net.DialTimeout("tcp", r.Host, 10*time.Second)
	}
	if err != nil {
		cleanupHandlerExit()
		e.logger.Warn("egress.upstream_dial", "host", host, "err", err)
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		cleanupHandlerExit()
		http.Error(w, "no hijacker", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		cleanupHandlerExit()
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		cleanupHandlerExit()
		return
	}

	e.trackTunnel(client, upstream)
	go func() {
		defer cleanupHandlerExit()
		defer func() { _ = upstream.Close() }()
		defer func() { _ = client.Close() }()
		defer e.untrackTunnel(client)
		bytesIn, bytesOut := tunnel(client, upstream, e.idleTimeout)
		// Bytes per host could fingerprint API usage; keep at Debug, not Info.
		e.logger.Debug("egress.allow",
			"host", host,
			"port", port,
			"bytes_in", bytesIn,
			"bytes_out", bytesOut,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()
}

// portAllowed returns true when port is in the allowed set. In production
// (testPorts == nil) only port 443 is accepted.
func (e *Egress) portAllowed(port string) bool {
	if e.testPorts != nil {
		_, ok := e.testPorts[port]
		return ok
	}
	return port == "443"
}

// tunnel pipes bytes bidirectionally and returns (clientToUpstream, upstreamToClient) totals.
// A rolling idle deadline (idleTimeout) bounds half-open or stalled tunnels.
//
// On half-close: the goroutine that reads from one side exits, and on its way
// out it pokes the OTHER side's read deadline. That unblocks the peer's
// blocking Read so the tunnel tears down promptly. Setting a deadline on the
// already-exiting goroutine's own connection does nothing useful.
func tunnel(client, upstream net.Conn, idleTimeout time.Duration) (int64, int64) {
	var (
		bytesC2U int64
		bytesU2C int64
		wg       sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer setReadDeadline(upstream) // unblock the peer goroutine reading from upstream
		bytesC2U, _ = copyWithIdleDeadline(upstream, client, idleTimeout)
	}()
	go func() {
		defer wg.Done()
		defer setReadDeadline(client) // unblock the peer goroutine reading from client
		bytesU2C, _ = copyWithIdleDeadline(client, upstream, idleTimeout)
	}()
	wg.Wait()
	return bytesC2U, bytesU2C
}

// copyWithIdleDeadline copies src to dst, bumping src's read deadline by
// idleTimeout after every successful read. A connection that goes quiet for
// longer than the timeout is reaped via i/o timeout.
func copyWithIdleDeadline(dst io.Writer, src net.Conn, idleTimeout time.Duration) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, rerr := src.Read(buf)
		if n > 0 {
			w, werr := dst.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total, werr
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return total, nil
			}
			return total, rerr
		}
	}
}

// setReadDeadline triggers the opposite-direction io.Copy to unblock when one
// side closes. Safe to call on closed conns.
func setReadDeadline(c net.Conn) {
	_ = c.SetReadDeadline(time.Now())
}

// atoi wraps strconv.Atoi, returning 0 on error (safe because net.SplitHostPort
// guarantees a numeric port string).
func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// dialViaParent opens a CONNECT tunnel to host:port through p. For
// HTTPS_PROXY=https://... the parent leg itself runs over TLS, so
// Proxy-Authorization headers don't traverse the wire in cleartext.
func dialViaParent(p *ParentProxy, hostPort string, timeout time.Duration) (net.Conn, error) {
	var conn net.Conn
	var err error
	switch p.URL.Scheme {
	case "https":
		// SNI uses the parent host (not the eventual target). Verify against
		// the parent's certificate.
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: timeout},
			Config:    &tls.Config{ServerName: p.URL.Hostname(), MinVersion: tls.VersionTLS12},
		}
		conn, err = dialer.Dial("tcp", p.URL.Host)
	case "http":
		conn, err = net.DialTimeout("tcp", p.URL.Host, timeout)
	default:
		return nil, fmt.Errorf("parent proxy: unsupported scheme %q", p.URL.Scheme)
	}
	if err != nil {
		return nil, fmt.Errorf("parent dial: %w", err)
	}
	req := "CONNECT " + hostPort + " HTTP/1.1\r\nHost: " + hostPort + "\r\n"
	if p.authHeader != "" {
		req += "Proxy-Authorization: " + p.authHeader + "\r\n"
	}
	req += "\r\n"
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("parent CONNECT write: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("parent CONNECT read: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		_ = conn.Close()
		return nil, fmt.Errorf("parent CONNECT status %d", resp.StatusCode)
	}
	_ = conn.SetDeadline(time.Time{})
	// If the parent pipelined data in the same TCP packet as the 200, those
	// bytes are sitting in `br`'s buffer and would be lost when we hand the
	// raw conn to the tunnel. Wrap so reads see the buffered bytes first.
	if buffered := br.Buffered(); buffered > 0 {
		head, perr := br.Peek(buffered)
		if perr == nil {
			conn = &bufferedConn{Conn: conn, head: append([]byte(nil), head...)}
		}
	}
	return conn, nil
}

// bufferedConn returns the bytes in head before falling through to the
// underlying Conn's Read. Used when bufio.Reader has buffered post-CONNECT
// bytes that would otherwise be discarded.
type bufferedConn struct {
	net.Conn
	head []byte
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	if len(b.head) > 0 {
		n := copy(p, b.head)
		b.head = b.head[n:]
		return n, nil
	}
	return b.Conn.Read(p)
}
