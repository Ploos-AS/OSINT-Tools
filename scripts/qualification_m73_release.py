#!/usr/bin/env python3
"""Static fail-closed qualification of the M7.3 release contract."""
from __future__ import annotations

from pathlib import Path
import re
import sys
import tomllib

WORKFLOW = Path('.github/workflows/release.yml')
CONTAINERFILE = Path('Containerfile')


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise AssertionError(f'{label}: missing {needle!r}')


def main() -> int:
    try:
        workflow = WORKFLOW.read_text(encoding='utf-8')
        containerfile = CONTAINERFILE.read_text(encoding='utf-8')
        with Path('pyproject.toml').open('rb') as handle:
            version = tomllib.load(handle)['project']['version']
        if not re.fullmatch(r'\d+\.\d+\.\d+', version):
            raise AssertionError(f'project version is not core SemVer: {version}')

        require(workflow, "tags:\n      - 'v*'", 'tag-only trigger')
        if re.search(r'^\s+branches:', workflow, flags=re.MULTILINE):
            raise AssertionError('release workflow must not publish from branches')
        if 'workflow_dispatch:' in workflow:
            raise AssertionError('release publication must remain tag-driven')

        for marker in (
            '^v([0-9]+)\\.([0-9]+)\\.([0-9]+)$',
            "test \"$version\" = \"$project_version\"",
            'sh scripts/qualify.sh',
            'python scripts/qualification_m72_backup_restore.py',
            'sh scripts/qualification_m62_browser.sh',
            'platforms: linux/amd64,linux/arm64',
            'ghcr.io/ploos-as/osint-tools',
            'ploosas/osint-tools',
            'DOCKERHUB_USERNAME',
            'DOCKERHUB_TOKEN',
            'sbom: true',
            'provenance: mode=max',
            'actions/attest-build-provenance@v2',
            'org.opencontainers.image.version=',
            'org.opencontainers.image.revision=',
            'org.opencontainers.image.source=',
            'Verify published manifests and digest equality',
            'Create GitHub release metadata',
        ):
            require(workflow, marker, 'release contract')

        for suffix in (
            '${{ needs.qualification.outputs.version }}',
            '${{ needs.qualification.outputs.major }}.${{ needs.qualification.outputs.minor }}',
            '${{ needs.qualification.outputs.major }}',
            'latest',
        ):
            require(workflow, f'${{{{ env.IMAGE_GHCR }}}}:{suffix}', 'GHCR tags')
            require(workflow, f'${{{{ env.IMAGE_DOCKERHUB }}}}:{suffix}', 'Docker Hub tags')

        require(containerfile, 'USER osint', 'non-root OCI runtime')
        require(containerfile, 'VOLUME ["/data"]', 'persistent data contract')
        if 'DOCKERHUB_TOKEN' in containerfile or 'GITHUB_TOKEN' in containerfile:
            raise AssertionError('registry credentials must not enter Containerfile')

        print(
            'M7.3 release automation|PASS|tag-only SemVer/version gate, full qualification, '
            'amd64+arm64 GHCR/Docker Hub publication, OCI tags/labels, SBOM/provenance, '
            'digest verification and release metadata verified'
        )
        return 0
    except Exception as exc:
        print(f'M7.3 release automation|FAIL|{type(exc).__name__}: {str(exc)[:300]}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
