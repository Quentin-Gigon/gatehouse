# Security policy

Gatehouse handles credentials. Please report vulnerabilities privately.

- **How:** use GitHub's "Report a vulnerability" (private security advisory) on this repository. Do not open a public issue.
- **Include:** version or commit, platform, what an attacker needs (which user, which access), and steps to reproduce with synthetic credentials only. Never send real credentials, cookies or vault files.
- **Scope:** anything that lets an agent, a web page or another local user obtain a credential value, use a credential outside its grant, bypass revocation, or read secrets from logs, API output or the audit history. Weaknesses already listed under "Residual risks" in `docs/THREAT_MODEL.md` are known; improvements to them are still welcome.
- **Response:** this is a volunteer project with no SLA. Expect an acknowledgement within a week.

Supported versions: only the latest release receives fixes while the project is pre-1.0.

## Release and dependency practice

- Two runtime dependencies (`aiohttp`, `cryptography`); the MCP adapter and client use the standard library only.
- Releases are tagged from `main` after CI passes on Linux and Apple Silicon macOS. Tags should be signed.
- Dependency updates are reviewed by hand; enable Dependabot alerts on the repository.
- No telemetry exists in the code base. The broker makes no network connections of its own; only the browser does.
