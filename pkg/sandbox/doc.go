// Package sandbox generates macOS Seatbelt profiles, exposes the canonical
// security policy (mandatory denies + default allowed domains), and wraps
// the sandbox-exec(1) primitive that ora uses to execute every wrapped
// AI coding CLI.
//
// External callers consume this package via two surfaces:
//
//   - DefaultPolicy() / DefaultBackend() for stable policy and execution
//     primitives. Use these when embedding ora's sandbox in another tool.
//   - GenerateProfile(opts) and Backend.Wrap(...) for low-level callers
//     that want to generate profiles and exec under them themselves.
//
// macOS-specific helpers (StartLogMonitor, SelfTestLogStream) are exposed
// as package-level functions; a future Linux/Landlock backend would justify
// moving them onto the Backend interface so the public API stays portable.
//
// Stability: this package is part of ora's public API. Exported symbols
// are stable within a major version.
package sandbox
