#!/usr/bin/env python3
"""Fail-closed static qualification for M7.5 release-candidate closure."""
from pathlib import Path
import re
import tomllib


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise AssertionError(f"{label}: missing {needle!r}")


def main() -> int:
    try:
        release = Path('.github/workflows/release.yml').read_text()
        qualification = Path('.github/workflows/qualification.yml').read_text()
        readme = Path('README.md').read_text()
        closure = Path('docs/M7_5_RELEASE_CANDIDATE.md').read_text()
        with Path('pyproject.toml').open('rb') as handle:
            current_version = tomllib.load(handle)['project']['version']

        if not re.fullmatch(r'\d+\.\d+\.\d+', current_version):
            raise AssertionError('current project version must be core SemVer')
        if current_version == '1.0.0' and not Path('scripts/qualification_m81_release_source.py').exists():
            raise AssertionError('final v1.0.0 version requires the M8.1 release-source handoff gate')

        for marker in (
            'OSINT_TOOLS_IMAGE: osint-tools:dev',
            'python scripts/qualification_m74_distribution.py',
            'python scripts/qualification_m75_release_candidate.py',
            'ghcr.io/ploos-as/osint-tools',
            'ploos1/osint-tools',
            'major="${BASH_REMATCH[1]}"',
            'minor="${BASH_REMATCH[2]}"',
        ):
            require(release, marker, 'release workflow')

        for marker in (
            'python scripts/qualification_m74_distribution.py',
            'python scripts/qualification_m75_release_candidate.py',
            'OSINT_TOOLS_IMAGE: osint-tools:dev',
        ):
            require(qualification, marker, 'qualification workflow')

        require(readme, 'M7 Release Engineering & Polish', 'README current state')
        require(readme, 'ploos1/osint-tools', 'README Docker Hub namespace')
        require(readme, 'No `v1.0.0` tag is created by M7.5', 'README release boundary')

        for marker in (
            'Forgejo is canonical',
            'Codeberg',
            'DOCKERHUB_USERNAME',
            'DOCKERHUB_TOKEN',
            'align the final project/runtime/API version to `1.0.0`',
            'No published `latest` or `1.0.0` image is implied',
        ):
            require(closure, marker, 'M7.5 closure')

        print('M7.5 release candidate closure|PASS|release gates, operator docs, registry namespaces, pre-v1 boundary and M8 handoff verified')
        return 0
    except Exception as exc:
        print(f'M7.5 release candidate closure|FAIL|{type(exc).__name__}: {str(exc)[:300]}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
