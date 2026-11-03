# Ubuntu deployment validation — 2026-11-02

Validation performed locally, without deploying to a remote server.

- `make check`: gofmt, go vet, Go tests with race detector.
- `make build`: native macOS development binaries.
- `make ubuntu-bundle`: CGO-disabled Linux ELF64 agents/Beacons for amd64 and arm64,
  default source configuration and Beacon installer, packed in ignored dist/.
- Shell syntax checked for installation/test scripts and shell blocks in the
  README/deployment guide.
- `make test-ubuntu`: ephemeral official Ubuntu 24.04 container, local synthetic
  OSV source and local HTTPS only. Ubuntu package installation prepares the test
  environment; no live vulnerability feeds are used by tests.

The container exercises separate publisher/HTTPS accounts, ACL denial of signing
and CA private keys to the HTTPS account, signed binary distribution, SPKI/script
pins, architecture selection, home-only agent setup/state/reports, real dpkg
inventory and a deliberately synthetic OpenSSL advisory. The example ID
TEST-ONLY-NOT-A-REAL-CVE and fixed version 999:1 are test data, not a security claim.

Tests reject wrong public-key pin, modified artifact, modified signed manifest,
and an expired correctly signed release. The installed binary remains unchanged
after rejection. A default dedicated shixpeer-ward-agent account and explicit existing-user
installation are exercised. Resident update/report loops run directly and create
bounded private home logs. Go tests cover loaded kernel signature parsing,
installed-vs-running distinction, pending reboot, IPv4/IPv6 proc socket fallback,
legacy migration preservation/rejection, log rotation and update-to-scan ordering.

Systemd unit syntax is checked by systemd-analyze. **Systemctl is stubbed inside
the container** because it has no systemd PID1: real reboot persistence and actual
systemd sandbox activation are not verified here. Test daemons run directly under
their Unix accounts. Both architectures are cross-built; execution uses the local
Docker platform. No host Docker socket is mounted into test containers, no host
ports are published, and no privileged container is used.

Local Mac legacy trust/checkpoint/report data was copied to ~/.shixpeer.ward/agent;
old data remains in ~/.shixpeer.ward/backups/legacy-macos-2026-11-02. The ignored
historical DB/key fixture moved from the project to ~/.shixpeer.ward/validation.
Migration does not refresh an expired database or erase rollback protection.
