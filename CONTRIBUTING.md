# Contributing to Shixpeer Ward

Thank you for helping make host monitoring private and understandable.
Project website: [shixpeer.com](https://shixpeer.com).

## Before changing code

Read [architecture](docs/architecture.md), [security](SECURITY.md), and the
[source adapter guide](docs/sources.md). Discuss new privileges, destinations,
contract changes, or database engines in an issue before implementing them.
The project intentionally uses files and in-process Go structures, not SQL.

Build with Go 1.26.10+. The race detector also needs a supported platform/C toolchain
(development only; release binaries use CGO_ENABLED=0). Run:

```sh
make fmt
make check
make build
```

Tests use synthetic advisories, temporary keys, and local TLS servers. Do not
make the test suite contact live vulnerability feeds. Never add private keys,
real host snapshots, credentials, or third-party data without appropriate rights.

## Commit messages

Use [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

```text
feat(beacon): add an OSV source adapter
fix(sync): preserve a source snapshot when refresh fails
docs(agent): explain offline collection
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`.
Keep the subject imperative and concise. A breaking change uses `!` and a
`BREAKING CHANGE:` footer describing migration. Keep commits focused and explain
non-obvious tradeoffs in the body. Do not commit generated runtime artifacts.

## Pull requests

Explain the trigger, resulting behavior, and meaningful tests. Add failure-case
coverage for parsing, network policy, rollback, and persistence changes.
Document new limits and unsupported coverage. Use `internal/` for implementation;
`pkg/` contains versioned data contracts, not a promise that every Go API is stable.

## Forks

A fork builds locally without contacting shixpeer.com. The Go module path identifies
this code; it is not a runtime endpoint. If changing that path, update imports too.
Use your own project identity, feeds, HTTPS identity and signing keys. Agents must
explicitly trust your public key; a fork must not claim to publish official data.
Preserve applicable license/NOTICE attribution and check upstream data terms.
