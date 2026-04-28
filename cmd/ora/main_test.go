package main

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersionFrom(t *testing.T) {
	t.Parallel()

	stub := func(info *debug.BuildInfo, ok bool) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) { return info, ok }
	}

	tests := []struct {
		name     string
		injected string
		info     *debug.BuildInfo
		ok       bool
		want     string
	}{
		{
			name:     "ldflags wins over build info",
			injected: "v1.2.3",
			info:     &debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}},
			ok:       true,
			want:     "v1.2.3",
		},
		{
			name:     "go install at tag falls back to module version",
			injected: "dev",
			info:     &debug.BuildInfo{Main: debug.Module{Version: "v0.2.0"}},
			ok:       true,
			want:     "v0.2.0",
		},
		{
			name:     "working tree build stays dev",
			injected: "dev",
			info:     &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			ok:       true,
			want:     "dev",
		},
		{
			name:     "empty main version stays dev",
			injected: "dev",
			info:     &debug.BuildInfo{Main: debug.Module{Version: ""}},
			ok:       true,
			want:     "dev",
		},
		{
			name:     "no build info available stays dev",
			injected: "dev",
			info:     nil,
			ok:       false,
			want:     "dev",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := resolveVersionFrom(tc.injected, stub(tc.info, tc.ok))
			if got != tc.want {
				t.Errorf("resolveVersionFrom(%q, …) = %q, want %q", tc.injected, got, tc.want)
			}
		})
	}
}
