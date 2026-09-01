from __future__ import annotations

import gzip
import stat
import tarfile
import zipfile
from pathlib import PurePosixPath

from .analysis import identify, safe_filename
from .budget import AnalysisBudget
from .store import ContentStore, UploadError


def suspicious_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    parts = normalized.split("/")
    return bool(normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":") or ".." in parts or any(ord(char) < 32 or ord(char) == 127 for char in name) or len(name) > 512)


def _child(store, objects: ContentStore, case_id: int, stream, name: str, allowance: int, budget: AnalysisBudget):
    content = objects.ingest_expanded(stream, max(0, allowance))
    budget.expanded_bytes += content["size"]
    detected = identify(content.pop("sample"), safe_filename(name))
    content.pop("created")
    from datetime import datetime, timezone
    at = datetime.now(timezone.utc).isoformat()
    analysis = {"size": content["size"], "hashes": content["hashes"], "filename": safe_filename(name), **detected, "ingested_at": at, "storage_id": content["storage_id"]}
    return store.add_file_ingestion(case_id, safe_filename(name), analysis)


def analyze_archive(store, objects: ContentStore, file_record: dict, detected_type: str, budget: AnalysisBudget, depth: int):
    if depth >= budget.limits.max_depth:
        return {"status": "limited", "reason": "max_depth", "depth": depth, "members": []}, []
    path = objects.physical_path(file_record["storage_id"])
    members, children = [], []
    try:
        if detected_type == "zip":
            with zipfile.ZipFile(path) as archive:
                infos = archive.infolist()
                for index, info in enumerate(infos):
                    if not budget.member():
                        members.append({"index": index, "status": "skipped", "reason": "max_members"}); break
                    mode = info.external_attr >> 16
                    file_type = stat.S_IFMT(mode)
                    special = file_type not in (0, stat.S_IFREG, stat.S_IFDIR)
                    item = {"index": index, "name": safe_filename(info.filename), "suspicious_path": suspicious_name(info.filename), "compressed_size": info.compress_size, "uncompressed_size": info.file_size, "compression_method": info.compress_type, "directory": info.is_dir(), "special": special, "encrypted": bool(info.flag_bits & 1), "crc": f"{info.CRC:08x}", "depth": depth}
                    if item["directory"]: item.update(status="skipped", reason="directory")
                    elif special: item.update(status="skipped", reason="special_member")
                    elif item["encrypted"]: item.update(status="skipped", reason="encrypted_member")
                    else:
                        allowance, reason = budget.allowance(info.compress_size)
                        try:
                            with archive.open(info) as stream: child = _child(store, objects, file_record["case_id"], stream, info.filename, allowance, budget)
                            item.update(status="analyzed", actual_bytes=child["size"], child_sha256=child["sha256"], child_file_id=child["id"]); children.append((child, item, depth + 1))
                        except UploadError: item.update(status="skipped", reason=reason)
                        except (RuntimeError, zipfile.BadZipFile, OSError): item.update(status="skipped", reason="malformed_archive")
                    members.append(item)
        elif detected_type == "tar":
            with tarfile.open(path, mode="r:*") as archive:
                for index, info in enumerate(archive):
                    if not budget.member(): members.append({"index": index, "status": "skipped", "reason": "max_members"}); break
                    special = not (info.isfile() or info.isdir())
                    item = {"index": index, "name": safe_filename(info.name), "suspicious_path": suspicious_name(info.name), "uncompressed_size": info.size, "directory": info.isdir(), "special": special, "depth": depth}
                    if info.isdir(): item.update(status="skipped", reason="directory")
                    elif special: item.update(status="skipped", reason="special_member")
                    else:
                        allowance, reason = budget.allowance()
                        try:
                            stream = archive.extractfile(info)
                            if stream is None: raise RuntimeError
                            with stream: child = _child(store, objects, file_record["case_id"], stream, info.name, allowance, budget)
                            item.update(status="analyzed", actual_bytes=child["size"], child_sha256=child["sha256"], child_file_id=child["id"]); children.append((child, item, depth + 1))
                        except UploadError: item.update(status="skipped", reason=reason)
                        except (RuntimeError, tarfile.TarError, OSError): item.update(status="skipped", reason="malformed_archive")
                    members.append(item)
        elif detected_type == "gzip":
            if not budget.member(): return {"status": "limited", "reason": "max_members", "depth": depth, "members": []}, []
            name = PurePosixPath(file_record["original_filename"]).stem or "gzip-member"
            allowance, reason = budget.allowance(file_record["size"])
            item = {"index": 0, "name": safe_filename(name), "suspicious_path": suspicious_name(name), "compressed_size": file_record["size"], "depth": depth}
            try:
                with gzip.open(path, "rb") as stream: child = _child(store, objects, file_record["case_id"], stream, name, allowance, budget)
                item.update(status="analyzed", actual_bytes=child["size"], child_sha256=child["sha256"], child_file_id=child["id"]); children.append((child, item, depth + 1))
            except UploadError: item.update(status="skipped", reason=reason)
            except (OSError, EOFError): item.update(status="skipped", reason="malformed_archive")
            members.append(item)
        else:
            return None, []
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError):
        return {"status": "failed", "reason": "malformed_archive", "depth": depth, "members": members}, children
    limited = next((item.get("reason") for item in members if item.get("reason") in {"max_members", "max_member_bytes", "max_total_bytes", "max_compression_ratio"}), None)
    return {"status": "limited" if limited else "success", "reason": limited, "depth": depth, "members": members, "actual_total_bytes": budget.expanded_bytes}, children
