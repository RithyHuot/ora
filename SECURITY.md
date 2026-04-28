# Security Policy

## Supported Versions

Only the latest tagged release receives security fixes. If you are running
a release older than the most recent tag, please update before reporting an
issue.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.** Public
disclosure before a fix is available puts every user of `ora` at risk.

To report a vulnerability:

1. Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
   on this repository, **or** email the maintainer at the address in the
   repository's GitHub profile.
2. Include:
   - A clear description of the vulnerability
   - Steps to reproduce
   - The version of `ora` and macOS you tested on
   - Whether you believe it is actively exploitable

You can expect:

- An initial acknowledgement within **72 hours**
- A coordinated disclosure timeline once the report is triaged
- Credit in the release notes and any published advisory, if you want it

## Threat Model and Known Limitations

For the full threat model, what `ora` does and does not protect against, the
mandatory deny lists, and known sandbox limitations, see
[`docs/SECURITY.md`](docs/SECURITY.md).
