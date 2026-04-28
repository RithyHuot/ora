# Contributing to ora

Thanks for your interest in contributing! This project welcomes bug reports,
feature suggestions, documentation improvements, and code contributions.

## Getting started

1. Fork the repository and clone your fork.
2. Ensure you have Go 1.23+ installed.
3. Run the test suite to verify your environment:
   ```sh
   go test ./...
   ```
4. On macOS, also run integration tests:
   ```sh
   go test -tags=integration ./...
   ```

## Development workflow

- Create a feature branch from `main`.
- Make your changes.
- Add or update tests for any new behavior.
- Run `go test ./...` and `golangci-lint run` (if installed).
- Open a pull request with a clear description of the change and why it was made.

## Code style

- Follow standard Go conventions (`gofmt`, `go vet`).
- Keep functions focused and packages cohesive.
- Comments explain **why**, not what.
- Handle errors explicitly — do not swallow exceptions.
- Store timestamps in UTC; convert to local time only on display.

## Adding a new provider

Provider support is a `pkg/providers.ProviderSpec` value. To add a new AI CLI:

1. Add an `AuthResolver` for the provider's auth dirs in `pkg/providers/auth.go`.
2. Add an entry to the builtin `registry` table in `pkg/providers/registry.go` with `Name`, `BinNames`, `AuthDirsRW`, `LoginCommand`, `OwnEnvKeys` (this provider's own API keys; the orchestrator strips every other provider's keys), and `ProbeHost` (for `ora doctor --probe`).
3. Add tests verifying the auth resolver and registry entry.

Out-of-tree code can register a provider without touching this repo:

```go
import "github.com/rithyhuot/ora/pkg/providers"

providers.Register(providers.ProviderSpec{
    Name:     "myco",
    BinNames: []string{"myco-cli"},
    AuthDirsRW: providers.AuthResolver(func(home string, _ map[string]string) []providers.AuthDirEntry {
        return []providers.AuthDirEntry{
            {Path: home + "/.myco", Kind: providers.AuthDirKindDir},
        }
    }),
    OwnEnvKeys: []string{"MYCO_API_KEY"},
    ProbeHost:  "api.myco.example",
})
```

## Public API surface

Anything under `pkg/` (`providers`, `sandbox`, `proxy`, `denials`) is treated as a public extension point. Breaking changes to those packages should be flagged in the PR and noted in `CHANGELOG.md`. Anything under `internal/` may be reorganized freely.

## Testing

- Unit tests should run on any platform (`go test ./...`).
- Integration tests are tagged with `//go:build integration` and darwin-only;
  they require a macOS host with `sandbox-exec`.
- Test unhappy paths: failures, malformed data, edge cases.

## Reporting security issues

Please see [`docs/SECURITY.md`](docs/SECURITY.md#reporting-security-issues) for
responsible disclosure instructions. Do not open public issues for security
vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the
MIT License.
