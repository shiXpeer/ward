"""Local-only bootstrap tests: never download or change system software."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

SOURCE = Path(__file__).with_name("relay-build-toolchain.sh").read_text()
DIGEST = "7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840"

class Toolchain(unittest.TestCase):
    def run_bootstrap(self, corrupt=False, download_fail=False, version="go1.20.1"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries = root / "bin"
            binaries.mkdir()
            scratch = root / "scratch"
            scratch.mkdir()
            archive = root / "fixture.tar.gz"
            payload = b'#!/bin/sh\necho "go version go1.27.4 linux/amd64"\n'
            with tarfile.open(archive, "w:gz") as output:
                entry = tarfile.TarInfo("go/bin/go")
                entry.size, entry.mode = len(payload), 0o755
                output.addfile(entry, io.BytesIO(payload))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            def executable(name, body):
                target = binaries / name
                target.write_text("#!/bin/bash\n" + body)
                target.chmod(0o755)
            if version is not None: executable("go", 'echo "go version ' + version + ' linux/amd64"\n')
            executable("uname", 'echo x86_64\n')
            executable("curl", 'printf "%s\\n" "$@" > "$CAPTURE"\n' + ('exit 22\n' if download_fail else 'while (( $# )); do if [[ $1 == --output ]]; then cp "$FIXTURE" "$2"; exit; fi; shift; done\n'))
            # Exercise a real digest comparison using the local archive.
            executable("sha256sum", 'read -r expected file\nactual=$(shasum -a 256 "$file")\n[[ ${actual%% *} == "$expected" ]]\n')
            source = SOURCE.replace(DIGEST, "0" * 64 if corrupt else digest)
            body = source + '\nfail() { echo "FAILED: $*" >&2; exit 1; }\nrelay_prepare_go "$SCRATCH" "$LOG"\n'
            env = dict(os.environ, PATH=str(binaries) + ":/usr/bin:/bin", FIXTURE=str(archive), SCRATCH=str(scratch), LOG=str(root / "log"), CAPTURE=str(root / "capture"))
            result = subprocess.run(["/bin/bash", "-e", "-c", body], env=env, text=True, capture_output=True)
            return result, (scratch / "go/bin/go").exists(), (root / "capture").read_text() if (root / "capture").exists() else ""

    def test_missing_or_old_go_bootstrap(self):
        result, extracted, arguments = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(extracted)
        self.assertIn("https://go.dev/dl/go1.27.4.linux-amd64.tar.gz", arguments)
        self.assertIn("--proto-redir\n=https", arguments)

    def test_missing_go_bootstrap(self):
        result, extracted, _ = self.run_bootstrap(version=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(extracted)

    def test_checksum_failure_never_extracts(self):
        result, extracted, _ = self.run_bootstrap(corrupt=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(extracted)
        self.assertIn("checksum mismatch", result.stderr)

    def test_download_failure(self):
        result, extracted, _ = self.run_bootstrap(download_fail=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(extracted)
        self.assertIn("Could not download Go", result.stderr)

    def test_current_go_skips_download(self):
        result, extracted, arguments = self.run_bootstrap(version="go1.26.10")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(extracted)
        self.assertEqual(arguments, "")

if __name__ == "__main__":
    unittest.main()
