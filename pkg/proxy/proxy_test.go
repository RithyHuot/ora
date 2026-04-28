package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rithyhuot/ora/pkg/denials"
)

// testCounter is a local denial Sink for tests. Counter is an ora-internal
// type; pkg/proxy tests need their own copy to avoid an internal/ import.
type testCounter struct {
	mu     sync.Mutex
	counts map[denials.Kind]int
}

func (c *testCounter) Push(_ context.Context, e denials.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts == nil {
		c.counts = make(map[denials.Kind]int)
	}
	c.counts[e.Kind]++
}

func (c *testCounter) Count(k denials.Kind) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[k]
}

func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestEgress_StartStop(t *testing.T) {
	e := &Egress{Allowed: []string{"localhost"}, Logger: newDiscardLogger()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	port, err := e.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if port == 0 {
		t.Fatal("expected non-zero port")
	}
	if err := e.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestEgress_StartTwiceReturnsError(t *testing.T) {
	e := &Egress{Allowed: []string{"localhost"}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := e.Start(ctx); err != nil {
		t.Fatalf("first Start failed: %v", err)
	}
	defer func() { _ = e.Stop() }()
	if _, err := e.Start(ctx); err == nil {
		t.Error("expected second Start to return an error")
	}
}

func TestEgress_DeniesPlainHTTP(t *testing.T) {
	e := &Egress{Allowed: []string{"example.com"}, Logger: newDiscardLogger()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	port, err := e.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.Stop() }()
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/anything", port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 on plain HTTP, got %d", resp.StatusCode)
	}
}

func TestEgress_AllowsConnectToAllowedHost(t *testing.T) {
	// Spin up a TLS upstream that returns a fixed body.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// write errors are unrecoverable in a handler; discard is intentional.
		_, _ = fmt.Fprint(w, "hello-from-upstream")
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamHost := upstreamURL.Hostname() // "127.0.0.1"
	upstreamPort := upstreamURL.Port()

	// testPorts is set here because httptest.NewTLSServer binds on a random
	// port (not 443). Production Egress only allows port 443; we must not
	// relax that policy, so we use the unexported testPorts field to permit
	// the dynamic port in this test only.
	e := &Egress{
		Allowed:   []string{"localhost"},
		Logger:    newDiscardLogger(),
		testPorts: map[string]struct{}{upstreamPort: {}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	port, err := e.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.Stop() }()

	// Build a client that uses our proxy and trusts the upstream's self-signed cert.
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	tr := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}

	// Override DNS — we want CONNECT to "localhost:<port>" to actually dial 127.0.0.1
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "localhost:") {
			addr = upstreamHost + addr[len("localhost"):]
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}

	resp, err := client.Get(fmt.Sprintf("https://localhost:%s/x", upstreamURL.Port()))
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-from-upstream" {
		t.Errorf("unexpected body: %q", body)
	}
}

func TestEgress_DeniesConnectToDisallowedHost(t *testing.T) {
	e := &Egress{Allowed: []string{"only-this.example"}, Logger: newDiscardLogger()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	port, err := e.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.Stop() }()

	// Raw CONNECT request — no helpful client wrapper.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(conn, "CONNECT denied.example:443 HTTP/1.1\r\nHost: denied.example:443\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 403") {
		t.Errorf("expected 403 response, got: %q", string(buf[:n]))
	}
}

func TestEgress_RejectsBeyondConcurrentTunnelCap(t *testing.T) {
	// Stand up an upstream that blocks until the test releases it, so
	// tunnels cannot drain on their own.
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	upstreamPort := upstream.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				<-release
			}(c)
		}
	}()

	e := &Egress{
		Allowed:              []string{"127.0.0.1"},
		Logger:               newDiscardLogger(),
		MaxConcurrentTunnels: 2,
		testPorts:            map[string]struct{}{fmt.Sprint(upstreamPort): {}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	port, err := e.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.Stop() }()

	dialConnect := func() (string, error) {
		c, derr := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if derr != nil {
			return "", derr
		}
		t.Cleanup(func() { _ = c.Close() })
		_, _ = fmt.Fprintf(c, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n",
			upstreamPort, upstreamPort)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, rerr := c.Read(buf)
		if rerr != nil {
			return "", rerr
		}
		return string(buf[:n]), nil
	}

	// First two CONNECTs should succeed.
	for i := 0; i < 2; i++ {
		resp, err := dialConnect()
		if err != nil {
			t.Fatalf("CONNECT %d: %v", i, err)
		}
		if !strings.HasPrefix(resp, "HTTP/1.1 200") {
			t.Fatalf("CONNECT %d: expected 200, got %q", i, resp)
		}
	}
	// Third CONNECT must hit the cap.
	resp, err := dialConnect()
	if err != nil {
		t.Fatalf("CONNECT 3: %v", err)
	}
	if !strings.HasPrefix(resp, "HTTP/1.1 503") {
		t.Errorf("expected 503 once tunnel cap hit, got: %q", resp)
	}
	// The cap rejection must increment NetworkBlocks. Operators rely on
	// this counter for "did the sandbox block anything" dashboards.
	if got := e.NetworkBlocks(); got < 1 {
		t.Errorf("expected NetworkBlocks >= 1 after tunnel_cap rejection, got %d", got)
	}
}

func TestEgress_TunnelIdleTimeoutReapsStalledConnection(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	upstreamPort := upstream.Addr().(*net.TCPAddr).Port
	connClosed := make(chan struct{}, 1)
	go func() {
		c, aerr := upstream.Accept()
		if aerr != nil {
			return
		}
		// Hold the conn open and silent. The proxy's idle deadline must
		// fire and tear it down. We detect that via a read returning EOF.
		go func() {
			buf := make([]byte, 16)
			_, _ = c.Read(buf)
			connClosed <- struct{}{}
			_ = c.Close()
		}()
	}()

	e := &Egress{
		Allowed:           []string{"127.0.0.1"},
		Logger:            newDiscardLogger(),
		TunnelIdleTimeout: 200 * time.Millisecond,
		testPorts:         map[string]struct{}{fmt.Sprint(upstreamPort): {}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	port, err := e.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.Stop() }()

	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = fmt.Fprintf(c, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n",
		upstreamPort, upstreamPort)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	rb := make([]byte, 256)
	if _, rerr := c.Read(rb); rerr != nil {
		t.Fatal(rerr)
	}
	// Now both sides go silent — wait for the proxy to reap the upstream.
	select {
	case <-connClosed:
	case <-time.After(2 * time.Second):
		t.Error("proxy did not reap idle tunnel within deadline")
	}
}

func TestEgress_DialsViaParentProxy(t *testing.T) {
	// Stand up a fake parent proxy that records the CONNECT line and forwards
	// the bytes through a local echo upstream.
	parent, parentURL := startFakeParentProxy(t)
	defer parent.Close()

	upstream, upstreamAddr := startFakeTLSEchoServer(t)
	defer func() { _ = upstream.Close() }()

	e := &Egress{
		Allowed:   []string{upstreamAddr.IP.String()},
		Parent:    &ParentProxy{URL: parentURL},
		testPorts: map[string]struct{}{"443": {}, fmt.Sprint(upstreamAddr.Port): {}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	port, err := e.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.Stop() }()

	// Send a CONNECT to ora's egress; verify parent saw the CONNECT.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamAddr, upstreamAddr)

	select {
	case got := <-parent.connectCalls:
		if !strings.Contains(got, upstreamAddr.String()) {
			t.Errorf("parent CONNECT line missing target host:port: %q", got)
		}
	case <-time.After(time.Second):
		t.Error("parent proxy never received CONNECT from egress")
	}
}

type fakeParent struct {
	listener     net.Listener
	connectCalls chan string
	closed       chan struct{}
}

func (f *fakeParent) Close() { _ = f.listener.Close(); <-f.closed }

func startFakeParentProxy(t *testing.T) (*fakeParent, *url.URL) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeParent{listener: ln, connectCalls: make(chan string, 1), closed: make(chan struct{})}
	go func() {
		defer close(f.closed)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				f.connectCalls <- string(buf[:n])
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	u, _ := url.Parse(fmt.Sprintf("http://%s", ln.Addr().String()))
	return f, u
}

func startFakeTLSEchoServer(t *testing.T) (net.Listener, *net.TCPAddr) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln, ln.Addr().(*net.TCPAddr)
}

func TestEgress_StopDoesNotLeakWaiterUnderHealthyShutdown(t *testing.T) {
	if testing.Short() {
		t.Skip("goroutine count test")
	}
	before := runtime.NumGoroutine()
	for range 5 {
		e := &Egress{Allowed: []string{"localhost"}}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if _, err := e.Start(ctx); err != nil {
			t.Fatal(err)
		}
		if err := e.Stop(); err != nil {
			t.Fatal(err)
		}
		cancel()
	}
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after-before > 2 {
		t.Errorf("goroutine count grew by %d after 5 Start/Stop cycles (before=%d, after=%d)",
			after-before, before, after)
	}
}

func TestNewEgress_SnapshotsConfig(t *testing.T) {
	t.Parallel()
	cfg := EgressConfig{Allowed: []string{"api.openai.com"}}
	e := NewEgress(cfg)
	cfg.Allowed[0] = "api.evil.com"
	if e.Allowed[0] != "api.openai.com" {
		t.Errorf("Allowed slice was not snapshotted: got %q", e.Allowed[0])
	}
}

func TestEgress_Start_RejectsCancelledContext(t *testing.T) {
	t.Parallel()
	e := NewEgress(EgressConfig{Allowed: []string{"api.openai.com"}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Start(ctx); err == nil {
		_ = e.Stop()
		t.Fatal("expected Start to reject cancelled ctx")
	}
}

func TestEgressStart_RejectsOverlyBroadAllowedDomain(t *testing.T) {
	t.Parallel()
	e := &Egress{Allowed: []string{"*.com"}}
	_, err := e.Start(context.Background())
	if err == nil {
		_ = e.Stop()
		t.Fatal("expected Egress.Start to reject *.com, got nil")
	}
	if !strings.Contains(err.Error(), "domain") {
		t.Errorf("error should mention the domain validation; got: %v", err)
	}
}

func TestTunnel_HalfCloseUnblocksPeer(t *testing.T) {
	t.Parallel()
	clientA, clientB := net.Pipe()
	upA, upB := net.Pipe()
	defer func() { _ = clientA.Close() }()
	defer func() { _ = clientB.Close() }()
	defer func() { _ = upA.Close() }()
	defer func() { _ = upB.Close() }()

	done := make(chan struct{})
	go func() {
		_, _ = tunnelForTest(clientB, upB, 30*time.Second)
		close(done)
	}()

	_ = clientA.Close()
	_ = upA.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("tunnel did not return within 2s of half-close; peer goroutine is leaking")
	}
}

func tunnelForTest(client, upstream net.Conn, idleTimeout time.Duration) (int64, int64) {
	return tunnel(client, upstream, idleTimeout)
}

func TestEgress_StopForcesCloseAfterShutdownTimeout(t *testing.T) {
	t.Parallel()
	e := &Egress{Allowed: []string{"localhost"}, Logger: newDiscardLogger(), ShutdownTimeout: 50 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- e.Stop() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Stop returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Stop hung — did not return within 3s")
	}
}

func TestEgress_StartReturnsErrorAfterStop(t *testing.T) {
	t.Parallel()
	e := &Egress{Allowed: []string{"localhost"}, Logger: newDiscardLogger()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Start(ctx); err == nil {
		_ = e.Stop()
		t.Error("expected second Start after Stop to return an error")
	}
}

func TestEgress_SnapshotsDenialsAtStart(t *testing.T) {
	counterA := &testCounter{}
	counterB := &testCounter{}
	e := &Egress{
		Allowed: []string{"example.com"},
		Denials: counterA,
		Logger:  newDiscardLogger(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	port, err := e.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.Stop() }()

	// Mutate after Start; later denies must NOT route to counterB.
	e.Denials = counterB

	// Trigger one denial via a non-allowlisted host.
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	req, _ := http.NewRequest(http.MethodConnect, "http://blocked.example/", nil)
	req.URL.Host = "blocked.example:443"
	_, _ = client.Do(req)

	if counterA.Count(denials.KindNetwork) == 0 {
		t.Error("expected counterA to receive the deny (snapshot at Start)")
	}
	if counterB.Count(denials.KindNetwork) != 0 {
		t.Errorf("counterB must NOT receive denies after Start; got %d", counterB.Count(denials.KindNetwork))
	}
}

// TestProxy_GoHTTPCollapsesConnectHostToURI pins the load-bearing invariant
// that ora's CONNECT validation depends on: Go's net/http server populates
// r.Host with the request-line URI (not the Host: header) for CONNECT
// requests, and deletes the Host: header from r.Header before the handler
// runs. This means handleConnect's r.Host use is safe — header smuggling
// is prevented at the parser layer, not at our handler layer.
//
// If a future Go release changes this precedence (e.g. preserves the
// header value in r.Host), this test fails and signals that
// pkg/proxy/proxy.go's handleConnect must be revisited to use a
// hand-rolled CONNECT parser.
//
// Reference: net/http/request.go's readRequest sets
// req.Host = req.URL.Host first, then falls back to header.
func TestProxy_GoHTTPCollapsesConnectHostToURI(t *testing.T) {
	t.Parallel()
	var (
		mu              sync.Mutex
		gotHost         string
		gotURLHost      string
		gotHeaderHostNE bool // true if r.Header still carried the smuggled Host
	)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotHost = r.Host
		if r.URL != nil {
			gotURLHost = r.URL.Host
		}
		// Per RFC 7230 §5.4 / Go net/http, Host is removed from r.Header
		// during ReadRequest. Detect any leak here.
		if vs, ok := r.Header["Host"]; ok && len(vs) > 0 {
			gotHeaderHostNE = true
		}
		// Hijack and close — we just want the parsed request, not a tunnel.
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	srv := &http.Server{Handler: h, ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Shutdown(context.Background()) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	// CONNECT line target = api.uri.example, Host header = api.header.example.
	// Two distinct, syntactically valid hostnames so the test can detect
	// whichever one ends up in r.Host.
	_, _ = fmt.Fprintf(conn, "CONNECT api.uri.example:443 HTTP/1.1\r\nHost: api.header.example:443\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.Copy(io.Discard, conn) // drain until server closes

	// Give the handler a beat to record before we lock and check.
	mu.Lock()
	defer mu.Unlock()

	const wantURI = "api.uri.example:443"
	if gotHost != wantURI {
		t.Errorf("r.Host = %q; want URI form %q. Go's net/http precedence may have changed — revisit handleConnect's r.Host use.", gotHost, wantURI)
	}
	if gotURLHost != wantURI {
		t.Errorf("r.URL.Host = %q; want URI form %q", gotURLHost, wantURI)
	}
	if gotHeaderHostNE {
		t.Errorf("r.Header still contains Host: a future Go release may have stopped stripping it. handleConnect must be revisited if so.")
	}
}

// TestEgress_ConnectAcceptsTrailingDotHost verifies that an RFC-1034
// canonical absolute hostname (trailing dot, e.g. "host.example.:443") is
// accepted by the matcher when the same host without the dot is
// allowlisted. Without trimming the matcher returns false and the user
// sees a 403 for a host they explicitly allowed.
func TestEgress_ConnectAcceptsTrailingDotHost(t *testing.T) {
	t.Parallel()
	e := &Egress{Allowed: []string{"only-this.example"}, Logger: newDiscardLogger()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	port, err := e.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.Stop() }()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	// Trailing-dot canonical absolute hostname; matcher must accept after trim.
	_, _ = fmt.Fprintf(conn, "CONNECT only-this.example.:443 HTTP/1.1\r\nHost: only-this.example.:443\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	// We have no real :443 listener for "only-this.example", so the dial
	// will fail with 502 (or similar). 403 would mean the matcher rejected
	// the trailing-dot form, which is the bug this task fixes.
	if strings.HasPrefix(string(buf[:n]), "HTTP/1.1 403") {
		t.Errorf("trailing-dot host was rejected by matcher (expected accept-then-fail-dial); got: %q", string(buf[:n]))
	}
}
