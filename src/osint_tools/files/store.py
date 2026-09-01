from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from typing import BinaryIO


class UploadError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


class ContentStore:
    chunk_size = 64 * 1024

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.objects = self.root / "sha256"
        self.temporary = self.root / ".tmp"
        for directory in (self.root, self.objects, self.temporary):
            directory.mkdir(parents=True, exist_ok=True)
            if directory.is_symlink() or not directory.is_dir():
                raise UploadError("unsafe_storage", "managed storage path is unsafe", 500)

    def ingest(self, stream: BinaryIO, content_length: int, max_bytes: int) -> dict:
        if content_length < 0:
            raise UploadError("invalid_content_length", "content length must be non-negative")
        if content_length > max_bytes:
            raise UploadError("upload_too_large", "upload exceeds maximum size", 413)
        hashes = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
        sample = bytearray()
        total = 0
        fd, temporary_name = tempfile.mkstemp(prefix="upload-", dir=self.temporary)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as output:
                remaining = content_length
                while remaining:
                    chunk = stream.read(min(self.chunk_size, remaining))
                    if not chunk:
                        raise UploadError("incomplete_upload", "upload ended before content length", 400)
                    total += len(chunk)
                    remaining -= len(chunk)
                    for digest in hashes.values():
                        digest.update(chunk)
                    if len(sample) < 8192:
                        sample.extend(chunk[:8192 - len(sample)])
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            digests = {name: digest.hexdigest() for name, digest in hashes.items()}
            sha256 = digests["sha256"]
            directory = self.objects / sha256[:2]
            directory.mkdir(mode=0o750, parents=True, exist_ok=True)
            if directory.is_symlink():
                raise UploadError("unsafe_storage", "managed storage path is unsafe", 500)
            destination = directory / sha256
            created = False
            try:
                os.link(temporary_path, destination)
                created = True
            except FileExistsError:
                if destination.is_symlink() or not destination.is_file() or destination.stat().st_size != total:
                    raise UploadError("storage_conflict", "stored object conflicts with content identifier", 500) from None
            return {"size": total, "hashes": digests, "sample": bytes(sample), "storage_id": f"sha256/{sha256[:2]}/{sha256}", "created": created}
        finally:
            temporary_path.unlink(missing_ok=True)

    def ingest_expanded(self, stream: BinaryIO, max_bytes: int) -> dict:
        hashes = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
        sample = bytearray()
        total = 0
        fd, temporary_name = tempfile.mkstemp(prefix="expanded-", dir=self.temporary)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as output:
                while True:
                    chunk = stream.read(min(self.chunk_size, max_bytes - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise UploadError("expanded_limit", "expanded content exceeded limit", 413)
                    for digest in hashes.values(): digest.update(chunk)
                    if len(sample) < 8192: sample.extend(chunk[:8192 - len(sample)])
                    output.write(chunk)
                output.flush(); os.fsync(output.fileno())
            digests = {name: digest.hexdigest() for name, digest in hashes.items()}
            sha256 = digests["sha256"]
            directory = self.objects / sha256[:2]
            directory.mkdir(mode=0o750, parents=True, exist_ok=True)
            if directory.is_symlink(): raise UploadError("unsafe_storage", "managed storage path is unsafe", 500)
            destination = directory / sha256
            created = False
            try:
                os.link(temporary_path, destination); created = True
            except FileExistsError:
                if destination.is_symlink() or not destination.is_file() or destination.stat().st_size != total:
                    raise UploadError("storage_conflict", "stored object conflicts with content identifier", 500) from None
            return {"size": total, "hashes": digests, "sample": bytes(sample), "storage_id": f"sha256/{sha256[:2]}/{sha256}", "created": created}
        finally:
            temporary_path.unlink(missing_ok=True)

    def physical_path(self, storage_id: str) -> Path:
        parts = storage_id.split("/")
        if len(parts) != 3 or parts[0] != "sha256" or len(parts[1]) != 2 or len(parts[2]) != 64 or parts[1] != parts[2][:2] or any(char not in "0123456789abcdef" for char in parts[2]):
            raise ValueError("invalid storage identifier")
        return self.root.joinpath(*parts)
