#!/usr/bin/env python3
"""M7.4 distribution/deployment contract qualification."""
from pathlib import Path


def require(text: str, *needles: str) -> None:
    for needle in needles:
        assert needle in text, f"missing required distribution contract: {needle}"


def main() -> int:
    try:
        compose = Path("compose.yaml").read_text()
        quadlet = Path("deploy/quadlet/osint-tools.container").read_text()
        install = Path("docs/INSTALL.md").read_text()
        distribution = Path("docs/DISTRIBUTION.md").read_text()

        require(compose, "${OSINT_TOOLS_IMAGE:-ghcr.io/ploos-as/osint-tools:latest}", "osint-tools-data:/data", "build:")
        assert "osint-tools:dev" not in compose

        require(quadlet, "Image=ghcr.io/ploos-as/osint-tools:latest", "Volume=osint-tools-data.volume:/data:Z", "NoNewPrivileges=true")
        assert "localhost/osint-tools:dev" not in quadlet

        require(install, "ghcr.io/ploos-as/osint-tools:1.0.0", "ploos1/osint-tools:1.0.0", "immutable", "/data")
        require(distribution, "Forgejo", "GitHub", "Codeberg", "ghcr.io/ploos-as/osint-tools", "ploos1/osint-tools", "Harbor", "linux/amd64", "linux/arm64")

        print("M7.4 distribution/docs|PASS|published-image Compose/Quadlet contract, immutable-tag guidance and Forgejo/GitHub/Codeberg + GHCR/Docker Hub model verified")
        return 0
    except Exception as exc:
        print(f"M7.4 distribution/docs|FAIL|{type(exc).__name__}: {str(exc)[:300]}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
