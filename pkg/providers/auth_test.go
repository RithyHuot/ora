package providers

import (
	"path/filepath"
	"testing"
)

func TestClaudeAuthDirs_IncludesDirAndJSON(t *testing.T) {
	got := claudeAuthDirs("/Users/alice", nil)
	want := []AuthDirEntry{
		{Path: "/Users/alice/.claude", Kind: AuthDirKindDir},
		{Path: "/Users/alice/.claude.json", Kind: AuthDirKindFile},
	}
	if len(got) != len(want) {
		t.Fatalf("claudeAuthDirs len=%d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("claudeAuthDirs[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestGeminiAuthDirs(t *testing.T) {
	got := geminiAuthDirs("/Users/alice", nil)
	if len(got) != 1 || got[0].Path != "/Users/alice/.gemini" || got[0].Kind != AuthDirKindDir {
		t.Errorf("geminiAuthDirs got %+v", got)
	}
}

func TestCodexAuthDirs_RespectsEnvOverride(t *testing.T) {
	got := codexAuthDirs("/Users/u", map[string]string{"CODEX_HOME": "/custom"})
	if len(got) != 1 || got[0].Path != "/custom" || got[0].Kind != AuthDirKindDir {
		t.Errorf("expected [/custom dir], got %+v", got)
	}
}

func TestCodexAuthDirs_DefaultWhenEnvUnset(t *testing.T) {
	got := codexAuthDirs("/Users/u", map[string]string{})
	want := "/Users/u/.codex"
	if len(got) != 1 || got[0].Path != want || got[0].Kind != AuthDirKindDir {
		t.Errorf("expected [%q dir], got %+v", want, got)
	}
}

func TestOpencodeAuthDirs_IncludesAllXDGRoots(t *testing.T) {
	got := opencodeAuthDirs("/Users/alice", nil)
	want := []string{
		filepath.Join("/Users/alice", ".config/opencode"),
		filepath.Join("/Users/alice", ".local/share/opencode"),
		filepath.Join("/Users/alice", ".local/state/opencode"),
		filepath.Join("/Users/alice", ".cache/opencode"),
	}
	if len(got) != len(want) {
		t.Fatalf("opencodeAuthDirs len=%d, want %d: %+v", len(got), len(want), got)
	}
	found := map[string]bool{}
	for _, e := range got {
		if e.Kind != AuthDirKindDir {
			t.Errorf("opencode entry %q should be Dir, got %v", e.Path, e.Kind)
		}
		found[e.Path] = true
	}
	for _, p := range want {
		if !found[p] {
			t.Errorf("opencodeAuthDirs missing %s; got %+v", p, got)
		}
	}
}

func TestNoAuth_ReturnsEmpty(t *testing.T) {
	if got := NoAuth("/Users/alice", nil); len(got) != 0 {
		t.Errorf("NoAuth got %+v, want empty", got)
	}
}

func TestCodexAuthDirs_RejectsRelativeEnv(t *testing.T) {
	out := codexAuthDirs("/Users/me", map[string]string{"CODEX_HOME": "../../etc"})
	for _, e := range out {
		if !filepath.IsAbs(e.Path) {
			t.Errorf("expected only absolute paths; got relative: %q", e.Path)
		}
	}
}

func TestCodexAuthDirs_HonorsAbsoluteEnv(t *testing.T) {
	out := codexAuthDirs("/Users/me", map[string]string{"CODEX_HOME": "/srv/codex"})
	if len(out) != 1 || out[0].Path != "/srv/codex" {
		t.Errorf("expected [/srv/codex]; got %+v", out)
	}
}
