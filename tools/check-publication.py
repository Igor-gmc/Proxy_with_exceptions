"""Inspect Git's staged blobs without printing secret values. Python 3.10+."""
import argparse
import json
from pathlib import PurePosixPath, Path
import re
import subprocess
import sys


def git(*args):
    return subprocess.check_output(['git', *args])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staged', action='store_true', required=True)
    parser.add_argument('--denylist', type=Path, help='Optional local JSON array; never commit this file')
    args = parser.parse_args()
    denied = json.loads(args.denylist.read_text(encoding='utf-8')) if args.denylist else []
    if not isinstance(denied, list) or any(not isinstance(s, str) or not s for s in denied):
        parser.error('Denylist must be an array of nonempty strings')
    roots = {'ProxyBridge', 'native', 'tests', 'integration', 'tools', 'licenses'}
    root_files = {'.gitignore', '.gitattributes', '.editorconfig', 'ProxyBridge.slnx',
                  'ARCHITECTURE.md', 'README.md', 'README.txt', 'HELP.txt',
                  'CHANGELOG.md', 'THIRD-PARTY.txt', 'SECURITY.md', 'Version.props',
                  'build.ps1', 'Recover-Internet.cmd', 'Start-Emulator-Proxy.cmd'}
    allowed_extensions = {'.cs', '.cpp', '.csproj', '.ps1', '.py', '.md', '.txt', '.props', '.cmd'}
    forbidden_parts = {'bin', 'obj', 'artifacts', 'dist', 'release', 'vendor', 'runtime',
                       'incidents', 'node_modules', '.aws', '.ssh', '.codex', '.agents',
                       '.vs', '.idea', '.vscode', '__pycache__'}
    patterns = {
        'private-key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----'),
        'github-token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b'),
        'aws-access-key': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
        'credential-url': re.compile(r'\b(?:https?|socks5?)://[^\s/@:]+:[^\s/@]+@', re.I),
        'inline-vpn-key': re.compile(r'<(?:tls-crypt|tls-auth|key)>', re.I),
    }
    failures = []
    entries = git('ls-files', '--stage', '-z').split(b'\0')
    count = 0
    for entry in entries:
        if not entry:
            continue
        metadata, raw_path = entry.split(b'\t', 1)
        mode, oid, stage = metadata.decode('ascii').split()
        name = raw_path.decode('utf-8')
        path = PurePosixPath(name)
        count += 1

        def fail(reason, line=None):
            failures.append(f'{name}' + (f':{line}' if line else '') + f': {reason}')

        if mode not in ('100644', '100755') or stage != '0':
            fail('unsupported file mode or unresolved index'); continue
        lower_parts = [part.lower() for part in path.parts]
        if ((len(path.parts) == 1 and name not in root_files)
                or (len(path.parts) > 1 and path.parts[0] not in roots)):
            fail('path outside publication allowlist')
        if any(p in forbidden_parts or '.env' in p or 'secret' in p or 'credential' in p
               for p in lower_parts):
            fail('private filename or directory')
        if (len(path.parts) == 2 and path.parts[0] in ('tests', 'integration')
                and path.suffix.lower() == '.md' and path.name != 'README.md'):
            fail('local historical report')
        icon = path.parent.as_posix() == 'ProxyBridge/Assets' and path.suffix in ('.ico', '.png')
        manifest = name == 'ProxyBridge/app.manifest'
        if name not in root_files and path.suffix.lower() not in allowed_extensions and not icon and not manifest:
            fail('file extension outside publication allowlist')
        size = int(git('cat-file', '-s', oid))
        if size > 2_000_000:
            fail('unexpectedly large file'); continue
        content = git('cat-file', 'blob', oid)
        if any(value.encode('utf-8') in content or value.encode('utf-16-le') in content for value in denied):
            fail('known private value')
        if icon:
            continue
        try:
            text = content.decode('utf-8-sig')
        except UnicodeDecodeError:
            fail('non-UTF8 source'); continue
        for line_number, line in enumerate(text.splitlines(), 1):
            for category, pattern in patterns.items():
                if pattern.search(line):
                    fail(category, line_number)
        if name in ('ProxyBridge/Settings.cs', 'ProxyBridge/Configuration/Settings.cs'):
            if not re.search(r'Default\s*=>\s*new\("",\s*\d+,\s*"",\s*"",\s*"http"\)', text):
                fail('default proxy credentials must be empty')
    if not count:
        failures.append('No staged files found')
    for failure in failures:
        print('FAIL', failure)
    print(f'{"FAIL" if failures else "PASS"}: {count} staged files, {len(failures)} findings; values are never printed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
