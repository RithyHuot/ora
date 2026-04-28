// Package trust implements trust-on-first-use for project-level .ora.toml
// files. Without this, walking into any cloned repository that ships its own
// .ora.toml would silently widen the user's sandbox policy (extra_domains,
// extra_writable, allow_npmrc, etc.) — defeating the threat model ora is
// supposed to enforce.
//
// The trust DB is a small TOML file at ~/.config/ora/trust.toml that records
// each trusted project config path together with a SHA-256 of its contents.
// Loading a project config requires the path AND content hash to match a
// trusted entry; any mismatch fails closed with a hint to run `ora trust`.
//
// The escape hatch ORA_TRUST_PROJECT_CONFIG=1 bypasses the trust check for
// CI / scripted contexts where prompting is not viable.
package trust

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
)

const (
	// EnvBypass disables the trust check when set to "1". Intended for CI.
	EnvBypass = "ORA_TRUST_PROJECT_CONFIG" //nolint:gosec // env var name, not a credential
)

// Entry is one trusted project config.
type Entry struct {
	Path    string `toml:"path"`
	SHA256  string `toml:"sha256"`
	AddedAt string `toml:"added_at"` // RFC3339 UTC
}

// DB is the on-disk trust database.
type DB struct {
	Entries []Entry `toml:"entry"`
}

// Path returns the trust DB path under homeDir.
func Path(homeDir string) string {
	return filepath.Join(homeDir, ".config", "ora", "trust.toml")
}

// Load reads the trust DB from homeDir. A missing file returns an empty DB,
// not an error — first-run users have nothing trusted yet.
//
// The open uses O_NOFOLLOW and the perm check runs against fstat on the open
// fd, so the trust DB cannot be substituted (or its permissions widened) in
// the window between perm check and read. A symlinked DB is refused; replace
// it with a regular file owned by the current user at 0600.
func Load(homeDir string) (*DB, error) {
	if homeDir == "" {
		return nil, fmt.Errorf("trust.Load: empty homeDir")
	}
	path := Path(homeDir)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // path is derived from homeDir+constant
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &DB{}, nil
		}
		// macOS surfaces O_NOFOLLOW-on-symlink as ELOOP; report it with the
		// same actionable message a symlink rejection deserves.
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf(
				"trust db %s is a symlink; replace with a regular file at 0600", path)
		}
		return nil, fmt.Errorf("open trust db %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("fstat trust db %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf(
			"trust: %s has perm %o; expected 0600 (no group/world bits)",
			path, perm)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read trust db %s: %w", path, err)
	}
	var db DB
	if err := toml.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("parse trust db %s: %w", path, err)
	}
	return &db, nil
}

// Save writes the trust DB atomically: write tmp → fsync → rename → fsync(parent).
// The parent directory is created (or its perms hardened to 0700) if needed.
func (db *DB) Save(homeDir string) error {
	if homeDir == "" {
		return fmt.Errorf("trust.Save: empty homeDir")
	}
	dst := Path(homeDir)
	parentDir := filepath.Dir(dst)
	if err := os.MkdirAll(parentDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", parentDir, err)
	}
	// MkdirAll is a no-op if the dir already exists; harden the perms.
	if err := os.Chmod(parentDir, 0o700); err != nil { //nolint:gosec // 0o700 is intentional dir perm
		return fmt.Errorf("chmod %s: %w", parentDir, err)
	}
	sort.SliceStable(db.Entries, func(i, j int) bool { return db.Entries[i].Path < db.Entries[j].Path })
	tmp, err := os.CreateTemp(parentDir, ".ora-trust-*.tmp")
	if err != nil {
		return fmt.Errorf("create tmp trust file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod trust tmp: %w", err)
	}
	enc := toml.NewEncoder(tmp)
	if err := enc.Encode(db); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode trust db: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync trust tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close trust tmp: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("rename trust db: %w", err)
	}
	cleanup = false
	// Best-effort fsync of the parent dir so the rename is durable. Some
	// filesystems (e.g. exfat) refuse this; ignore errors there.
	if d, err := os.Open(parentDir); err == nil { //nolint:gosec // parentDir is derived from homeDir+constant
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// ErrSymlinkRejected is returned by Check and Add when the target path is
// a symlink. The trust DB binds (path, content-hash) tuples; allowing the
// path to be a symlink means a relinked symlink with identical content
// passes the check, even though it now points elsewhere on disk.
var ErrSymlinkRejected = errors.New("trust path must not be a symlink")

// hashFileNoSymlink returns the SHA-256 of path, refusing to follow a symlink.
// Callers must use this rather than os.ReadFile so the trust DB never blesses
// a path whose target can be swapped without tripping a hash mismatch.
func hashFileNoSymlink(path string) (string, error) {
	bytes, err := readFileNoSymlink(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}

// HashFile returns the hex-encoded SHA-256 of the file at path. Returns
// ErrSymlinkRejected if path is a symlink.
func HashFile(path string) (string, error) {
	return hashFileNoSymlink(path)
}

// CheckResult describes the outcome of a Check call.
type CheckResult int

const (
	// Trusted means the path matches a trusted entry with the same hash.
	Trusted CheckResult = iota
	// NotTrusted means the path is not in the trust DB at all.
	NotTrusted
	// HashMismatch means the path is in the trust DB but the hash differs
	// (the file changed since it was trusted; possibly malicious modification).
	HashMismatch
)

// Check returns the trust state for projectConfigPath against db. It reads
// the file (refusing symlinks) and hashes the bytes; callers that already
// have the file contents in memory should prefer CheckBytes to avoid a
// second read.
func (db *DB) Check(projectConfigPath string) (CheckResult, error) {
	clean := filepath.Clean(projectConfigPath)
	got, err := hashFileNoSymlink(clean)
	if err != nil {
		return NotTrusted, err
	}
	return db.CheckHash(clean, got), nil
}

// CheckBytes verifies trust for projectConfigPath using the supplied
// contents. The caller is responsible for confirming the path was not a
// symlink before reading. This avoids a TOCTOU between the trust check and
// the config parse: if both consume the same byte slice, an attacker
// swapping the file on disk between hash and parse can't bypass trust.
func (db *DB) CheckBytes(projectConfigPath string, contents []byte) CheckResult {
	clean := filepath.Clean(projectConfigPath)
	sum := sha256.Sum256(contents)
	return db.CheckHash(clean, hex.EncodeToString(sum[:]))
}

// CheckHash compares the supplied SHA-256 hash against the trust DB entry
// for projectConfigPath.
func (db *DB) CheckHash(projectConfigPath, hash string) CheckResult {
	clean := filepath.Clean(projectConfigPath)
	for _, e := range db.Entries {
		if filepath.Clean(e.Path) == clean {
			if subtle.ConstantTimeCompare([]byte(e.SHA256), []byte(hash)) == 1 {
				return Trusted
			}
			return HashMismatch
		}
	}
	return NotTrusted
}

// ReadProjectConfig reads path while refusing to follow a symlink. Returns
// the bytes plus the hex-encoded SHA-256, suitable for handing to
// CheckBytes / parseConfig together so the trust check and the config
// parse always see the same content.
func ReadProjectConfig(path string) ([]byte, string, error) {
	bytes, err := readFileNoSymlink(path)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(bytes)
	return bytes, hex.EncodeToString(sum[:]), nil
}

// Add records projectConfigPath in the trust DB with its current hash.
// If the path is already present, the hash and timestamp are refreshed
// (re-trust after intentional edit).
func (db *DB) Add(projectConfigPath string) error {
	clean := filepath.Clean(projectConfigPath)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("trust path must be absolute: %q", clean)
	}
	hash, err := hashFileNoSymlink(clean)
	if err != nil {
		return fmt.Errorf("hash %s: %w", clean, err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for i, e := range db.Entries {
		if filepath.Clean(e.Path) == clean {
			db.Entries[i].SHA256 = hash
			db.Entries[i].AddedAt = now
			return nil
		}
	}
	db.Entries = append(db.Entries, Entry{Path: clean, SHA256: hash, AddedAt: now})
	return nil
}

// Remove deletes the entry for projectConfigPath. Returns true if an entry
// was removed.
func (db *DB) Remove(projectConfigPath string) bool {
	clean := filepath.Clean(projectConfigPath)
	out := db.Entries[:0]
	removed := false
	for _, e := range db.Entries {
		if filepath.Clean(e.Path) == clean {
			removed = true
			continue
		}
		out = append(out, e)
	}
	db.Entries = out
	return removed
}

// BypassActive reports whether the trust check is currently bypassed via env.
// Accepts the same boolean forms as the rest of ora's env layer: 1, true,
// yes, on (case-insensitive). Anything else (including unset, "0", "false",
// "garbage") returns false.
func BypassActive() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvBypass))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func readFileNoSymlink(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close() //nolint:errcheck

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() {
		return nil, fmt.Errorf("trust: %s is not a regular file", path)
	}
	return io.ReadAll(f)
}
