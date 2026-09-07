#!/usr/bin/env python3

from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]

with (ROOT / "pyproject.toml").open("rb") as f:
    project_version = tomllib.load(f)["project"]["version"]

init_text = (ROOT / "src/osint_tools/__init__.py").read_text()
server = (ROOT / "src/osint_tools/server.py").read_text()
qualify = (ROOT / "scripts/qualify.sh").read_text()
qualification = (ROOT / ".github/workflows/qualification.yml").read_text()
release = (ROOT / ".github/workflows/release.yml").read_text()
m8 = (ROOT / "docs/M8_QUALIFICATION.md").read_text()

match = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
assert match, "__version__ not found"
runtime_version = match.group(1)

assert project_version == "1.0.0", f"pyproject version is {project_version}"
assert runtime_version == "1.0.0", f"runtime version is {runtime_version}"

assert 'server_version = f"OSINT-Tools/{__version__}"' in server
assert '"version": __version__, "milestone": "M8"' in server

assert (
    'assert i["version"] == "1.0.0" and i["milestone"] == "M8"'
    in qualify
)
assert '"M8.1 runtime version"' in qualify
assert "API reports 1.0.0/M8" in qualify

assert "python scripts/qualification_m81_release_source.py" in qualification
assert "python scripts/qualification_m80_release_readiness.py" not in qualification

assert "python scripts/qualification_m81_release_source.py" in release
assert "platforms: linux/amd64,linux/arm64" in release
assert "ghcr.io/ploos-as/osint-tools" in release
assert "ploos1/osint-tools" in release
assert "DOCKERHUB_USERNAME" in release
assert "DOCKERHUB_TOKEN" in release

assert "M8.1 freezes the candidate source version at `1.0.0`" in m8
assert "does **not** create or push `v1.0.0`" in m8

print(
    "M8.1 exact release source|PASS|"
    "1.0.0 package/runtime/API alignment and normal/tag qualification gates verified"
)
