#!/usr/bin/env python3
"""M7.2 release-state backup/restore and upgrade qualification."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import urllib.request

from qualification_m61_runtime import Client

PASSWORD = "qualification-m72-sentinel"
PAYLOAD = b"M7.2 persistent uploaded evidence\n"


def docker(*args: str) -> str:
    return subprocess.check_output(
        ["docker", *args], stderr=subprocess.STDOUT, text=True
    ).strip()


def wait_ready(name: str) -> str:
    port = docker("port", name, "8080/tcp").rsplit(":", 1)[1]
    base = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            with urllib.request.urlopen(base + "/healthz", timeout=2) as response:
                assert response.status == 200
            return base
        except Exception:
            time.sleep(0.5)
    raise AssertionError(
        "M7.2 runtime did not become healthy: " + docker("logs", "--tail", "20", name)[-2000:]
    )


def start(name: str, data: Path) -> str:
    docker(
        "run",
        "-d",
        "--name",
        name,
        "-p",
        "127.0.0.1::8080",
        "-e",
        "OSINT_TOOLS_AUTH_ENABLED=true",
        "-v",
        f"{data}:/data",
        "osint-tools:dev",
    )
    return wait_ready(name)


def archive(source: Path, backup_root: Path) -> Path:
    backup = backup_root / "osint-tools-data.tgz"
    docker(
        "run",
        "--rm",
        "--user",
        "0",
        "--entrypoint",
        "sh",
        "-v",
        f"{source}:/data:ro",
        "-v",
        f"{backup_root}:/backup",
        "osint-tools:dev",
        "-c",
        "tar -C /data -czf /backup/osint-tools-data.tgz .",
    )
    assert backup.is_file() and backup.stat().st_size > 0
    return backup


def restore(target: Path, backup_root: Path) -> None:
    docker(
        "run",
        "--rm",
        "--user",
        "0",
        "--entrypoint",
        "sh",
        "-v",
        f"{target}:/data",
        "-v",
        f"{backup_root}:/backup:ro",
        "osint-tools:dev",
        "-c",
        # A host bind mount may give the restore root host-runner ownership even when
        # archive members preserve UID/GID. Normalize the complete restored boundary
        # to the image's non-root application identity, then retain host qualification
        # read/traverse access without granting write access to other users.
        "tar -C /data -xzf /backup/osint-tools-data.tgz && chown -R 10001:10001 /data && chmod -R a+rX /data",
    )


def verify_restored_payload(target: Path, expected_hash: str) -> None:
    """Verify exact restored CAS bytes from inside a read-only root helper."""
    output = docker(
        "run",
        "--rm",
        "--user",
        "0",
        "--entrypoint",
        "sh",
        "-v",
        f"{target}:/data:ro",
        "osint-tools:dev",
        "-c",
        "find /data/files -type f -exec sha256sum {} \\;",
    )
    hashes = {line.split()[0] for line in output.splitlines() if line.strip()}
    assert expected_hash in hashes, "restored uploaded bytes are missing"


def clear_container_owned_data(target: Path) -> None:
    """Remove bind-mounted content as root before host TemporaryDirectory cleanup."""
    docker(
        "run",
        "--rm",
        "--user",
        "0",
        "--entrypoint",
        "sh",
        "-v",
        f"{target}:/data",
        "osint-tools:dev",
        "-c",
        "rm -rf /data/* /data/.[!.]* /data/..?*",
    )


def verify_schema(data: Path) -> None:
    with sqlite3.connect(data / "osint-tools.db") as conn:
        version = conn.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()[0]
        assert version == "9"
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def main() -> int:
    name = f"osint-m72-{os.getpid()}"
    try:
        # Explicitly re-run the immutable schema-8 -> current schema migration as
        # part of the M7.2 release gate, rather than only relying on historical CI.
        subprocess.run(
            ["python", "scripts/qualification_m61_migration_runtime.py"], check=True
        )

        with tempfile.TemporaryDirectory(prefix="osint-m72-") as temp:
            root = Path(temp)
            root.chmod(0o755)
            source = root / "source"
            restored = root / "restored"
            backup_root = root / "backup"
            for directory in (source, restored, backup_root):
                directory.mkdir()
                directory.chmod(0o777)

            try:
                base = start(name, source)
                admin = Client(base)
                admin.ok(
                    "POST",
                    "/api/v1/auth/bootstrap",
                    {"username": "m72admin", "password": PASSWORD},
                    201,
                )
                admin.login("m72admin", PASSWORD)
                analyst_id = admin.ok(
                    "POST",
                    "/api/v1/admin/users",
                    {"username": "m72analyst", "password": PASSWORD, "role": "analyst"},
                    201,
                )["id"]
                analyst = Client(base).login("m72analyst", PASSWORD)

                team = admin.ok(
                    "POST",
                    "/api/v1/admin/teams",
                    {"name": "M7.2 restore team", "description": "backup sentinel"},
                    201,
                )
                team_path = f"/api/v1/admin/teams/{team['id']}"
                admin.ok("POST", team_path + "/members", {"user_id": analyst_id}, 201)

                case = admin.ok(
                    "POST",
                    "/api/v1/cases",
                    {"name": "M7.2 backup restore case", "description": "must survive"},
                    201,
                )
                case_path = f"/api/v1/cases/{case['id']}"
                admin.ok(
                    "POST",
                    case_path + "/acl",
                    {
                        "principal_type": "team",
                        "principal_id": team["id"],
                        "access": "editor",
                    },
                    201,
                )
                admin.ok("POST", case_path + "/notes", {"body": "persistent note"}, 201)
                file_row = admin.ok("POST", case_path + "/files", PAYLOAD, 201)
                file_id = file_row["id"]
                assert analyst.ok("GET", case_path + "/access")["effective_access"] == "editor"
                assert analyst.ok("GET", f"/api/v1/files/{file_id}")["id"] == file_id
                before_info = admin.ok("GET", "/api/v1/info")

                docker("stop", name)
                verify_schema(source)
                archive(source, backup_root)
                docker("rm", name)

                # Restore into a new empty persistent root; the source is deliberately
                # left unused so successful verification cannot read the original data.
                restore(restored, backup_root)
                verify_schema(restored)
                expected_hash = hashlib.sha256(PAYLOAD).hexdigest()
                verify_restored_payload(restored, expected_hash)

                base = start(name, restored)
                admin = Client(base).login("m72admin", PASSWORD)
                analyst = Client(base).login("m72analyst", PASSWORD)
                after_info = admin.ok("GET", "/api/v1/info")
                assert after_info["version"] == before_info["version"]
                assert after_info.get("milestone") == before_info.get("milestone")

                restored_case = admin.ok("GET", case_path)
                assert restored_case["name"] == "M7.2 backup restore case"
                assert any(note["body"] == "persistent note" for note in restored_case["notes"])
                assert analyst.ok("GET", case_path + "/access")["effective_access"] == "editor"
                assert analyst.ok("GET", f"/api/v1/files/{file_id}")["id"] == file_id
                assert any(
                    t["name"] == "M7.2 restore team"
                    for t in admin.ok("GET", "/api/v1/admin/teams")
                )

                docker("restart", name)
                base = wait_ready(name)
                analyst = Client(base).login("m72analyst", PASSWORD)
                assert analyst.ok("GET", case_path + "/access")["effective_access"] == "editor"
                assert analyst.ok("GET", f"/api/v1/files/{file_id}")["id"] == file_id

                print(
                    "M7.2 backup/restore/upgrade|PASS|schema8 upgrade, stopped full-/data archive, clean restore, users/team/ACL/case/note/upload bytes and restart verified"
                )
            finally:
                # The application image runs as UID 10001. Clean bind-mounted trees
                # from a root helper so host-side TemporaryDirectory cleanup cannot
                # mask the actual gate result.
                try:
                    docker("rm", "-f", name)
                except Exception:
                    pass
                for directory in (source, restored):
                    try:
                        clear_container_owned_data(directory)
                    except Exception:
                        pass
        return 0
    except Exception as exc:
        print(f"M7.2 backup/restore/upgrade|FAIL|{type(exc).__name__}: {str(exc)[:300]}")
        return 1
    finally:
        try:
            docker("rm", "-f", name)
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
