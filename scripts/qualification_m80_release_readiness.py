#!/usr/bin/env python3
"""Fail-closed static qualification for M8.0 final-release qualification plan."""
from pathlib import Path
import tomllib


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise AssertionError(f"{label}: missing {needle!r}")


def main() -> int:
    try:
        with Path("pyproject.toml").open("rb") as handle:
            project_version = tomllib.load(handle)["project"]["version"]
        qualification = Path(".github/workflows/qualification.yml").read_text()
        release = Path(".github/workflows/release.yml").read_text()
        m8 = Path("docs/M8_QUALIFICATION.md").read_text()

        if project_version == "1.0.0":
            raise AssertionError("M8.0 planning gate must run before the final version-alignment commit")
        require(qualification, "python scripts/qualification_m80_release_readiness.py", "qualification workflow")
        for marker in (
            "linux/amd64",
            "linux/arm64",
            "Docker Hub repository `ploos1/osint-tools`",
            "Forgejo canonical `main` commit equals this qualified release commit",
            "GitHub and Codeberg mirrors",
            "DOCKERHUB_USERNAME",
            "DOCKERHUB_TOKEN",
            "same OCI digest",
            "does **not** create or push the release tag",
            "align `pyproject.toml`, `osint_tools.__version__`, and `/api/v1/info` to `1.0.0`",
        ):
            require(m8, marker, "M8 qualification contract")
        for marker in (
            "platforms: linux/amd64,linux/arm64",
            "ghcr.io/ploos-as/osint-tools",
            "ploos1/osint-tools",
            "DOCKERHUB_USERNAME",
            "DOCKERHUB_TOKEN",
        ):
            require(release, marker, "release workflow")
        print("M8.0 final qualification plan|PASS|release-version, architecture, mirror, registry and immutable-tag gates are explicit")
        return 0
    except Exception as exc:
        print(f"M8.0 final qualification plan|FAIL|{type(exc).__name__}: {str(exc)[:300]}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
