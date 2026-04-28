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

func TestOpencodeAuthDirs_IncludesConfigAndDataHome(t *testing.T) {
	got := opencodeAuthDirs("/Users/alice", nil)
	wantConfig := filepath.Join("/Users/alice", ".config/opencode")
	wantData := filepath.Join("/Users/alice", ".local/share/opencode")
	if len(got) != 2 {
		t.Fatalf("opencodeAuthDirs len=%d, want 2: %+v", len(got), got)
	}
	foundConfig, foundData := false, false
	for _, e := range got {
		if e.Kind != AuthDirKindDir {
			t.Errorf("opencode entry %q should be Dir, got %v", e.Path, e.Kind)
		}
		if e.Path == wantConfig {
			foundConfig = true
		}
		if e.Path == wantData {
			foundData = true
		}
	}
	if !foundConfig || !foundData {
		t.Errorf("opencodeAuthDirs got %+v; missing %s or %s", got, wantConfig, wantData)
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
