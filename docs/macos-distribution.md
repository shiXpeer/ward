# macOS distribution

User flow: open https://ward.shixpeer.com → download the matching DMG → drag
Ward into Applications → open it and choose notification/login preferences.
The first-launch screen requests no administrator or Full Disk Access rights.
System settings remain under user control.

## One-time setup on the release Mac

1. In Xcode → Settings → Accounts → Manage Certificates, install a **Developer ID
   Application** certificate with its private key. `Apple Development` cannot be
   used for this distribution. Confirm using `security find-identity -v -p codesigning`.
   Apple may require the Account Holder to create this certificate. A team
   administrator/developer role alone may not be sufficient; select the correct
   Team or ask its owner to provision the identity securely.
2. Store notarization credentials using `xcrun notarytool store-credentials ward-notary`.
   Enter credentials locally; never put them in source control or chat.
3. Sparkle 2.10.1 is pinned by SHA-256. Its release-signing key uses Keychain account
   `com.shixpeer.ward`. It has already been created on the current release Mac.
   Securely back it up using Sparkle's official key export mechanism; do not
   generate a replacement for an existing app. Only its public key ships in Info.plist.

## Build and notarize

```sh
export WARD_SIGN_IDENTITY='Developer ID Application: Your Name (TEAMID)'
export WARD_NOTARY_PROFILE=ward-notary
bash packaging/macos/release.sh 0.5.0 500 arm64
# On the same Mac, Intel cross-build:
bash packaging/macos/release.sh 0.5.0 500 x86_64
```

Version/build numbers must increase. The script signs nested helpers with hardened
runtime, notarizes/staples the app and DMG, assesses Gatekeeper, then signs the final
DMG using Sparkle Ed25519 and records SHA-256. It fails before publishing if any
verification fails. Archives and keys are not committed. Build architectures
sequentially because they share the intermediate app bundle.

```sh
bash packaging/macos/publish.sh 0.5.0 500 arm64
bash packaging/macos/publish.sh 0.5.0 500 x86_64
```

Uploads go to a GitHub draft, without overwriting an existing asset. Review and
publish it. Existing portable-agent automation uploads into an existing draft when present.
Create the draft before pushing its tag when both macOS and portable artifacts
should be reviewed and published together.

## Publish metadata

Use `packaging/macos/update-feed.py VERSION BUILD ARCH DMG` after publication.
It verifies Apple stapling and Sparkle's archive signature and updates the local
site's architecture-specific appcast/download links. Other architectures are retained. Deploy only
`site/` to the backend deployment's `site/` directory (do not replace its volumes).
Run `bash packaging/macos/deploy-site.sh SSH_HOST` to upload the static site.
The edge serves `/` and `/releases/` locally; the database routes are unchanged.
The appcast is on Ward; DMGs come directly from GitHub Releases.

The default developer build has no Sparkle dependency. Set `WARD_SPARKLE=1` to
exercise integration locally. Do not publish ad-hoc developer DMGs as ready releases.

## Verify on another Mac

Download via the website, mount DMG, copy to Applications and launch. Confirm no
unidentified-developer workaround is required, notification/login choices work,
Database selects Ward, and the Ward menu contains “Check for Ward Updates…”.
Test an older notarized build against a newer signed release: quit/install/relaunch
must succeed and preserve local reports/settings. A corrupt archive must fail.
End-to-end notarization/update validation requires the distribution certificate
and two real signed release builds; fixture tests alone do not establish this.
