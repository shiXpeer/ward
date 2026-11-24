#!/usr/bin/env python3
"""Publish metadata only for a stapled, signed DMG; no private keys in files."""
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

version, build, arch, archive = sys.argv[1:]
if not (re.fullmatch(r'\d+\.\d+\.\d+', version) and re.fullmatch(r'[1-9]\d*', build)):
    raise SystemExit('Invalid version/build')
if arch not in ('arm64', 'x86_64'):
    raise SystemExit('Invalid architecture')
root = pathlib.Path(__file__).resolve().parents[2]
archive = pathlib.Path(archive).resolve()
if archive.name != f'Ward-{version}-{arch}.dmg':
    raise SystemExit('Unexpected archive name')
subprocess.run(['xcrun', 'stapler', 'validate', str(archive)], check=True)
tool = str(root / 'dist/sparkle-2.10.1/bin/sign_update')
signature = subprocess.check_output([tool, '--account', 'com.shixpeer.ward', '-p', str(archive)], text=True).strip()
subprocess.run([tool, '--account', 'com.shixpeer.ward', '--verify', str(archive), signature], check=True)
release = json.loads(subprocess.check_output(['gh', 'release', 'view', f'v{version}',
    '--repo', 'shiXpeer/ward', '--json', 'isDraft,assets'], text=True))
if release['isDraft'] or not any(a['name'] == archive.name and a['size'] == archive.stat().st_size for a in release['assets']):
    raise SystemExit('Publish the matching GitHub release asset before advertising it')
site = root / 'packaging/docker/site/releases'
namespace = 'http://www.andymatuschak.org/xml-namespaces/sparkle'
ET.register_namespace('sparkle', namespace)
q = lambda name: '{' + namespace + '}' + name
feed = site / f'appcast-{arch}.xml'
tree = ET.parse(feed)
channel = tree.getroot().find('channel')
for item in list(channel.findall('item')):
    if item.findtext(q('hardwareRequirements')) == arch:
        old = item.findtext(q('version'))
        if old is not None and int(build) <= int(old):
            raise SystemExit('Build must increase')
        channel.remove(item)
url = f'https://github.com/shiXpeer/ward/releases/download/v{version}/{archive.name}'
item = ET.SubElement(channel, 'item')
for key, value in [('title', f'Ward {version}'), (q('version'), build),
                   (q('shortVersionString'), version), (q('minimumSystemVersion'), '14.0'),
                   (q('hardwareRequirements'), arch)]:
    ET.SubElement(item, key).text = value
ET.SubElement(item, 'enclosure', {'url': url, 'length': str(archive.stat().st_size),
                                'type': 'application/octet-stream', q('edSignature'): signature})
tree.write(feed, encoding='utf-8', xml_declaration=True)
data = json.loads((site / 'downloads.json').read_text())
data['downloads'] = [x for x in data['downloads'] if x['arch'] != arch]
data['downloads'].append({'arch': arch, 'version': version, 'url': url,
                          'sha256': hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest()})
(site / 'downloads.json').write_text(json.dumps(data, indent=2) + '\n')
print('Ready: deploy site/ to the Ward edge')
