# Shixpeer Ward contributor guidance

- Go 1.26.10+, standard `cmd/`, `internal/`, `pkg/` layout; website https://shixpeer.com.
- Program names: shixpeer-ward-agent and shixpeer-ward-beacon.
- Keep inventory local. No telemetry, per-package remote queries, remote execution,
  automatic host updates, implicit privilege escalation, or hidden outbound requests.
- No Postgres, SQLite or other database engine. Use bounded file-backed state and
  in-process structures; defaults live only under the executing account’s ~/.shixpeer.ward/.
- Preserve source-specific evidence, versions, distro context and withdrawal status.
  Never treat missing coverage, an empty source list or failed sync as “safe”.
- Use independent TLS and artifact-signing keys. Do not bypass signature/expiry/
  rollback checks or silently allow HTTPS downgrade/unknown destinations.
- Tests use local fixtures/TLS servers. Do not run tests against production hosts.
- Before completion: gofmt, go vet, meaningful tests including failure cases.
  Run `make check`; build when command/package wiring changes.
- No keys, real host inventories, credentials or generated state in source/release assets.
- Follow CONTRIBUTING.md, Conventional Commits and explicit contract versioning.
- The ignored `tests/` directory is a historical experiment, not part of the Go product.
