#!/usr/bin/env python3
"""Local fixture: fallback metadata uses Ward; installer URL remains direct."""
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parent.parent
source = (root / 'apps/macos/BrewCurl.sh').read_text()
with tempfile.TemporaryDirectory() as directory:
    wrapper = pathlib.Path(directory) / 'curl-fixture'
    wrapper.write_text(source.replace('exec /usr/bin/curl "${args[@]}"',
                                      'printf "%s\\n" "${args[@]}"'))
    arguments = ['--fail', '--header', 'Accept: application/json',
                 'https://formulae.brew.sh/api/internal/packages.arm64_fixture.jws.json',
                 'https://vendor.example/app.zip']
    actual = subprocess.check_output(['bash', str(wrapper), *arguments], text=True).splitlines()
    expected = arguments.copy()
    expected[3] = 'https://ward.shixpeer.com/v1/homebrew/internal/packages.arm64_fixture.jws.json'
    assert actual == expected, actual
print('PASS: Homebrew fallback metadata uses Ward; installer URL unchanged')
