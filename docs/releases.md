# Source, binary and data releases

## Source repository

Before the first public push:

1. Review `.gitignore`, staged files, licenses and `NOTICE`.
2. Exclude private keys, local data, real inventories and editor/build directories.
3. Run `make check` and the local TLS quickstart.
4. Enable GitHub private vulnerability reporting and branch protection.
5. Use Conventional Commits; see `CONTRIBUTING.md`.

The historical Bash experiment remains on the developer machine under ignored
`tests/`; it is not part of this Go product, build, public source package or CI.

## Software release

Use Semantic Versioning: choose a tag from the 0.4 series matching the change. Document
breaking command/schema/state changes explicitly. Do not label a scaffold as stable.

The tag workflow runs checks, builds Linux/macOS amd64/arm64 binaries with no CGO,
packages the three Go binaries (agent, Beacon and relay), licenses/notices, READMEs, default source configurations, documentation, schemas and the public demo fixture, writes SHA-256 checksums and creates a GitHub release.
It has no feed-signing key and does not publish a database. Pre-release tags with
`-...` are marked prerelease. GitHub Actions are pinned to reviewed commits.
Checksums detect corruption; binary-release attestation/signing is not yet configured.

Before pushing a tag, review test output, changed privileges/destinations, reproducibility,
archive contents, docs and rollback instructions. GitHub must supply the normal
scoped release token; never commit a PAT. Workflows are configuration, not proof that
remote CI has already run. A fork publishes to its own repository context.

## Database release

Use a separate data repository and `data-YYYYMMDDTHHMMSSZ` tags. See
[distribution](distribution.md). Data publishes follow the snapshot's signed
revision/expiry, independently of application version. Review source data licenses,
source health/staleness and artifact size. Publish only `manifest.json` and its referenced `db-*.wdb` files.
Never put signing/TLS keys or host inventories in releases, Pages, LFS or Git history.
Prefer release assets over continually committing large compressed snapshots to Git.

Compatibility is explicit: signed manifest v3 describes indexed disk format 3.
The obsolete JSON feeds are not accepted by current binaries. Rebuild both programs
and use fresh state when migrating to 0.4. Changes require fixtures/tests, a documented
contract version and rollout instructions. Private compiled-cache revisions are
independent of the public disk format; cached projections must be invalidated when
normalization semantics change.
