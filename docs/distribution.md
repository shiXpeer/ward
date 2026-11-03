# Signed disk snapshots: HTTPS and GitHub

Protocol **v3**, disk format **3**, requires both binaries from version 0.4. Use fresh
state directories when migrating from JSON feeds; legacy files are not auto-deleted.

```text
manifest.json                    exact-byte Ed25519 envelope
db-<sha256>.wdb                   immutable indexed file with compressed blocks
```

The manifest binds publication profile, generation, source check times, monotonic
revision, creation/expiry, optional immutable HTTPS base URL, and each object's
slot, file SHA-256/bytes and row count. The envelope's
`payload` and `signature` are base64 strings. Verify exact payload bytes, not
reserialized JSON. Limits: 1 MiB envelope, 896 objects, 128 MiB per file, 4 GiB total file safety cap, TTL up to seven days. These are
rejection bounds, not expected runtime memory requirements.

Objects already contain compressed blocks and are delivered directly, without a
second compression/decompression pass. The agent streams each file to disk with a
fixed 32 KiB buffer, checking exact size/SHA-256, header, row count and disk index.
It renames verified files and syncs their directory before switching `current.json`.
That pointer also binds the accepted revision to the authenticated payload bytes.
Validation/transport failures leave the installed database/checkpoint unchanged.
Storage errors after the final rename can leave commit durability uncertain: retain
objects and retry without resetting state. Interrupted downloads may leave verified
objects for reuse; an update prunes everything outside the installed and targeted
generations. Readers hold a shared lock while accessing the current database.
Cached private immutable files are trusted after installation (header/size checked
on reuse); local filesystem compromise is outside the transport trust boundary.
Row/block CRCs detect damaged data during lookup.
Lookup rejects expired installed manifests. No expiry/signature bypass flag exists.

The HTTPS server exposes only `GET /v1/manifest.json` and
`GET /v1/db-<sha256>.wdb`. It never serves private state or keys. Default bind is
`127.0.0.1:8443`. Keys for HTTPS and signing remain separate.

## Local export

```sh
bin/shixpeer-ward-beacon export -state .local/beacon -out .local/public \
  -signing-key .local/pki/signing.key -ttl 24h
```

Export refuses a failed last sync or source checks older than 24 hours. A successful
source check is not proof the upstream database itself is complete/current. Keep
source provenance and monitor coverage. Export writes immutable objects first and
replaces the manifest last. Existing objects are reused when their content matches.
Public historical objects are not automatically removed: retain them until every
manifest referencing them has expired plus your download grace period.

## GitHub/static HTTPS

Use a dedicated **data** repository. Publish only the exported public files; review
upstream redistribution licenses. Export with a final immutable release base URL:

```sh
bin/shixpeer-ward-beacon export -state .local/beacon -out .local/export-TAG \
  -signing-key .local/pki/signing.key \
  -base-url https://github.com/OWNER/DATA_REPOSITORY/releases/download/TAG/ -ttl 24h
```

After replacing the `OWNER`, `DATA_REPOSITORY` and `TAG` placeholders, prepare a
reviewable draft and upload only the exported assets:

```sh
gh release create TAG --repo OWNER/DATA_REPOSITORY --draft --title TAG \
  --notes 'Signed Shixpeer Ward public vulnerability data.'
gh release upload TAG --repo OWNER/DATA_REPOSITORY \
  .local/export-TAG/manifest.json .local/export-TAG/db-*.wdb
```

Review source licenses, coverage, expiry and the uploaded asset list before publishing:

```sh
gh release edit TAG --repo OWNER/DATA_REPOSITORY --draft=false --latest
```
 No GitHub upload happens automatically. Do not
use Git history as the archive for every database generation. A persistent static
mirror reuses unchanged URLs across publications; a fresh release must include all
objects referenced by its manifest. Keep within the host's current service limits.

```sh
bin/shixpeer-ward-agent pull -state .local/download \
  -feed-url https://github.com/OWNER/DATA_REPOSITORY/releases/latest/download/manifest.json \
  -trusted-key .local/pki/feed.pub \
  -allow-hosts release-assets.githubusercontent.com,objects.githubusercontent.com
```

Additional redirect hosts are explicit, never wildcarded. Provision `feed.pub`
through a trusted channel; use `-ca-file` only for a private CA. Public HTTPS mirrors
need no private key to serve already signed artifacts. Offline transport currently
requires copying the export to a trusted local HTTPS mirror. No `file://` bypass.

The layout has at most 896 database objects plus the manifest, below GitHub's
[current 1,000 assets per release limit](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).
Each database object is also below its per-file limit.
