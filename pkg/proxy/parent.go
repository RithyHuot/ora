package proxy

import (
	"encoding/base64"
	"log/slog"
	"net/url"
	"strings"
)

// ParentProxy is the resolved upstream HTTP proxy ora dials through (instead
// of directly hitting the destination) when the host environment specifies
// HTTPS_PROXY / HTTP_PROXY.
//
// The struct is read-only after construction by ResolveParentProxy; mutating
// fields after the value has been handed to Egress.Parent is undefined.
type ParentProxy struct {
	URL     *url.URL
	NoProxy []string // hostnames or .suffixes that bypass the parent proxy

	// authHeader is the precomputed "Basic <b64>" header derived from URL
	// userinfo at resolve time; it is unexported so a struct-literal caller
	// cannot bypass the encoding by setting a raw string. Use
	// HasEmbeddedCredentials to query whether auth is present.
	authHeader string
}

// shouldBypass reports whether host matches any NO_PROXY entry. This matches
// Go stdlib (`golang.org/x/net/http/httpproxy`) semantics:
//   - An entry starting with "." (".internal") matches the host if it ends
//     with that suffix or equals the suffix without the leading dot.
//   - A bare entry ("example.com") matches the host exactly OR matches any
//     subdomain of it (api.example.com).
//
// Operators porting a working NO_PROXY=example.com from curl or other Go
// tooling expect subdomain matching by default.
func (p *ParentProxy) shouldBypass(host string) bool {
	host = strings.ToLower(host)
	for _, n := range p.NoProxy {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		if strings.HasPrefix(n, ".") {
			if strings.HasSuffix(host, n) || host == n[1:] {
				return true
			}
			continue
		}
		if host == n || strings.HasSuffix(host, "."+n) {
			return true
		}
	}
	return false
}

// HasEmbeddedCredentials reports whether the resolved parent proxy URL
// carries username/password in its userinfo section. Such credentials are
// forwarded to the parent on every CONNECT regardless of target host; if
// the parent URL itself is attacker-controlled (e.g. injected via shell
// rc), those credentials leak. Callers should warn the operator at
// startup when this returns true.
func (p *ParentProxy) HasEmbeddedCredentials() bool {
	return p != nil && p.authHeader != ""
}

// ResolveParentProxy reads HTTPS_PROXY (preferred), HTTP_PROXY, and NO_PROXY
// from the supplied env (case-insensitive) and returns a ParentProxy or nil.
// Returns nil for proxy URLs without an http or https scheme; a parse-failure
// path emits a slog.Warn so silent typos don't lull operators into thinking
// they're proxying when they are going direct.
func ResolveParentProxy(env map[string]string) *ParentProxy {
	pick := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := env[k]; ok && v != "" {
				return v
			}
			if v, ok := env[strings.ToLower(k)]; ok && v != "" {
				return v
			}
		}
		return ""
	}
	raw := pick("HTTPS_PROXY", "HTTP_PROXY")
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		slog.Warn("proxy: HTTPS_PROXY parse failed; running direct", "value", raw, "err", err)
		return nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		slog.Warn("proxy: HTTPS_PROXY scheme not supported; running direct",
			"scheme", u.Scheme, "value", raw)
		return nil
	}
	auth := ""
	if u.User != nil {
		user := u.User.Username()
		pass, _ := u.User.Password()
		creds := user + ":" + pass
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
	}
	noProxyRaw := pick("NO_PROXY")
	noProxy := []string{}
	if noProxyRaw != "" {
		for _, p := range strings.Split(noProxyRaw, ",") {
			noProxy = append(noProxy, strings.TrimSpace(p))
		}
	}
	return &ParentProxy{URL: u, authHeader: auth, NoProxy: noProxy}
}
