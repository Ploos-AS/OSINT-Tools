import hashlib
import io
from pathlib import Path

import pytest

from osint_tools.files.analysis import identify, safe_filename
from osint_tools.files.service import FileError, ingest_file
from osint_tools.files.store import ContentStore, UploadError
from osint_tools.providers.virustotal import VirusTotalProvider
from osint_tools.storage import Store


def setup(tmp_path):
    store = Store(tmp_path / "data" / "db.sqlite")
    objects = ContentStore(tmp_path / "data" / "files")
    case = store.create_case("files")
    return store, objects, case


def test_streaming_hashes_zero_and_exact_limit(tmp_path):
    objects = ContentStore(tmp_path / "files")
    empty = objects.ingest(io.BytesIO(b""), 0, 0)
    assert empty["hashes"] == {name: hashlib.new(name, b"").hexdigest() for name in ("md5", "sha1", "sha256")}
    content = b"streamed content"
    result = objects.ingest(io.BytesIO(content), len(content), len(content))
    assert result["size"] == len(content)
    for name in ("md5", "sha1", "sha256"):
        assert result["hashes"][name] == hashlib.new(name, content).hexdigest()


def test_oversize_and_incomplete_cleanup(tmp_path):
    objects = ContentStore(tmp_path / "files")
    with pytest.raises(UploadError) as oversized:
        objects.ingest(io.BytesIO(b"abcd"), 4, 3)
    assert oversized.value.code == "upload_too_large"
    with pytest.raises(UploadError) as incomplete:
        objects.ingest(io.BytesIO(b"ab"), 4, 4)
    assert incomplete.value.code == "incomplete_upload"
    assert list(objects.temporary.iterdir()) == []
    assert list(objects.objects.rglob("?")) == []


def test_content_addressing_and_physical_deduplication(tmp_path):
    objects = ContentStore(tmp_path / "files")
    content = b"same bytes"
    first = objects.ingest(io.BytesIO(content), len(content), 100)
    second = objects.ingest(io.BytesIO(content), len(content), 100)
    assert first["storage_id"] == second["storage_id"]
    assert first["created"] is True and second["created"] is False
    assert objects.physical_path(first["storage_id"]).read_bytes() == content
    assert len([path for path in objects.objects.rglob("*") if path.is_file()]) == 1


@pytest.mark.parametrize("filename", ["../../etc/passwd", "/etc/passwd", "..\\..\\windows\\system.ini", "a/b/c.txt", "nul\x00name", "x" * 2000, "unicøde-文件.txt", ".hidden", "control\nname"])
def test_hostile_filenames_are_metadata_only(tmp_path, filename):
    store, objects, case = setup(tmp_path)
    result = ingest_file(store, objects, case["id"], io.BytesIO(b"hello"), 5, filename, 100)
    assert result["storage_id"].startswith("sha256/")
    assert ".." not in result["storage_id"]
    assert "/etc" not in result["storage_id"]
    assert len(result["original_filename"]) <= 512
    assert "\x00" not in result["original_filename"]
    assert objects.physical_path(result["storage_id"]).is_file()


def test_type_detection_and_extension_mismatch():
    png = identify(b"\x89PNG\r\n\x1a\nrest", "photo.png")
    assert png == {"extension": ".png", "detected_type": "png", "mime_type": "image/png", "extension_mismatch": False}
    assert identify(b"\x89PNG\r\n\x1a\n", "photo.pdf")["extension_mismatch"] is True
    assert identify(b"plain UTF-8", "note.txt")["detected_type"] == "text"
    assert identify(b"", "empty")["mime_type"] == "application/x-empty"


def test_file_association_artifact_persistence_and_hash_pivot(tmp_path):
    store, objects, case = setup(tmp_path)
    first = ingest_file(store, objects, case["id"], io.BytesIO(b"payload"), 7, "one.bin", 100)
    second = ingest_file(store, objects, case["id"], io.BytesIO(b"payload"), 7, "two.bin", 100)
    assert first["id"] != second["id"]
    assert first["target_id"] == second["target_id"]
    assert first["storage_id"] == second["storage_id"]
    analysis = Store(store.path).get_file_analysis(first["id"])
    assert analysis["type"] == "file_analysis" and analysis["source"] == "local"
    assert analysis["data"]["hashes"]["sha256"] == first["sha256"]
    target = store.get_target(first["target_id"])
    assert target["type"] == "hash" and target["normalized"] == first["sha256"]
    assert "hash" in VirusTotalProvider.supported_target_types


def test_invalid_case_does_not_consume_or_store(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    objects = ContentStore(tmp_path / "files")
    stream = io.BytesIO(b"hostile")
    with pytest.raises(FileError) as caught:
        ingest_file(store, objects, 999, stream, 7, "x", 100)
    assert caught.value.code == "case_not_found"
    assert stream.tell() == 0
    assert not any(path.is_file() for path in objects.objects.rglob("*"))


def test_database_failure_removes_new_publication(tmp_path):
    class BrokenStore:
        def get_case(self, case_id): return {"id": case_id}
        def add_file_ingestion(self, *args): raise RuntimeError("database unavailable")
    objects = ContentStore(tmp_path / "files")
    with pytest.raises(RuntimeError):
        ingest_file(BrokenStore(), objects, 1, io.BytesIO(b"new"), 3, "x", 100)
    assert not any(path.is_file() for path in objects.objects.rglob("*"))


def test_managed_store_rejects_symlink_root(tmp_path):
    real = tmp_path / "real"; real.mkdir()
    link = tmp_path / "files"; link.symlink_to(real, target_is_directory=True)
    with pytest.raises(UploadError) as caught:
        ContentStore(link)
    assert caught.value.code == "unsafe_storage"
