package proxy

import "testing"

// FuzzResolveParentProxy ensures arbitrary HTTPS_PROXY values don't panic.
func FuzzResolveParentProxy(f *testing.F) {
	for _, v := range []string{
		"",
		"http://proxy:3128",
		"https://user:pw@corp:8443",
		"ftp://nope",
		"//host-only",
		"\x00\xff\x01",
		"http://[::1]:8080",
	} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_ = ResolveParentProxy(map[string]string{"HTTPS_PROXY": raw})
	})
}
