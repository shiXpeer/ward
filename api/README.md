# Current contracts

`manifest-v3.schema.json` describes the **decoded** signed payload. The transport
object is `{ "payload": "<base64 exact JSON>", "signature": "<base64 Ed25519>" }`.
Signature verification precedes schema/time/size/path checks. JSON schema alone
cannot enforce cryptographic binding, unique slots, aggregate budgets or rollback.
The application additionally enforces these constraints.

Indexed disk format **3** (`WARDDB03`), little endian:

| Region | Layout |
| --- | --- |
| Header, 40 bytes | magic 8, block count u64, data offset u64, data bytes u64, row count u64 |
| Index, 48 bytes/block | first key SHA-256 32, relative data offset u64, compressed bytes u32, compressed CRC32 u32 |
| Data | independently gzip-compressed blocks; frames: key SHA-256 32, value bytes u32, value CRC32 u32, value |

The sorted index hashes `group + NUL + key`. Package keys are `ecosystem + NUL + name`.
Slot is the group plus the first hash byte (`p-00` through `p-ff`, likewise `v/r`; `s-00` through `s-7f` uses seven prefix bits).
Sorted keys share blocks, each normally up to 64 KiB before compression. The index
stores each block's first key hash. Lookup includes the predecessor block and filters
full hashes while streaming; keys may span multiple blocks.
A single large version-set frame is allowed up to 8 MiB plus framing. JSON rows are
limited to 64 KiB; exact version sets use `WVST` binary encoding (count u32, n+1 u32
string offsets, sorted unique UTF-8 strings). No whole index is mapped into memory.

Each artifact's SHA-256 binds the entire disk file including index.
The agent verifies that before installation. Local row/block CRCs detect accidental
corruption; they are not cryptographic signatures.

`legacy/` contains obsolete JSON feed and manifest schemas for reference. Current
CLI commands do not serve, accept or assemble those formats. Use fresh state for 0.4.

## Local report v1

`report-v1.schema.json` describes private local scan output. It is unsigned host
inventory and evidence, not a distribution feed. See [scan semantics](../docs/scanning.md).

## Signed installation releases

See [agents-v1](agents-v1.md) for the canonical signed Linux release, bootstrap
pins, expiry/rollback and fixed installation requests. Agent binaries are only
installed by an explicit administrator action, never by vulnerability data.
