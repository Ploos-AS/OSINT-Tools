import gzip
import io
import tarfile
import zipfile

import pytest
from PIL import Image

from osint_tools.files.budget import AnalysisLimits
from osint_tools.files.service import ingest_file
from osint_tools.files.store import ContentStore
from osint_tools.storage import Store


def environment(tmp_path):
    store = Store(tmp_path / "data" / "db.sqlite")
    objects = ContentStore(tmp_path / "data" / "files")
    case = store.create_case("structured")
    return store, objects, case


def upload(store, objects, case, raw, name, limits=None):
    return ingest_file(store, objects, case["id"], io.BytesIO(raw), len(raw), name, 10 * 1024 * 1024, limits or AnalysisLimits())


def zip_bytes(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries: archive.writestr(name, data)
    return output.getvalue()


def artifact(store, file_id, artifact_type):
    values = store.get_file_analysis(file_id)["structured"]
    return next(value["data"] for value in values if value["type"] == artifact_type)


def test_zip_inventory_child_hash_dedup_and_provenance(tmp_path):
    store, objects, case = environment(tmp_path)
    raw = zip_bytes([("hello.txt", b"hello"), ("copy.txt", b"hello")])
    parent = upload(store, objects, case, raw, "files.zip")
    analysis = artifact(store, parent["id"], "archive_analysis")
    assert [member["status"] for member in analysis["members"]] == ["analyzed", "analyzed"]
    assert analysis["members"][0]["child_sha256"] == analysis["members"][1]["child_sha256"]
    loaded = store.get_case(case["id"])
    contains = [r for r in loaded["relationships"] if r["relation"] == "contains"]
    assert len(contains) == 1 and contains[0]["artifact_id"] is not None
    assert len([path for path in objects.objects.rglob("*") if path.is_file()]) == 2


def test_reupload_keeps_per_file_results_and_deduplicates_objects(tmp_path):
    store, objects, case = environment(tmp_path)
    raw = zip_bytes([("hello.txt", b"hello")])
    first = upload(store, objects, case, raw, "first.zip")
    second = upload(store, objects, case, raw, "second.zip")
    assert first["id"] != second["id"] and first["storage_id"] == second["storage_id"]
    assert len([item for item in store.get_file_analysis(first["id"])["structured"] if item["type"] == "archive_analysis"]) == 1
    assert len([item for item in store.get_file_analysis(second["id"])["structured"] if item["type"] == "archive_analysis"]) == 1
    assert len([path for path in objects.objects.rglob("*") if path.is_file()]) == 2


@pytest.mark.parametrize("name", ["../../etc/passwd", "/etc/passwd", "C:\\Windows\\System32\\x", "nested/../../escape"])
def test_archive_traversal_names_are_never_paths(tmp_path, name):
    store, objects, case = environment(tmp_path)
    parent = upload(store, objects, case, zip_bytes([(name, b"safe")]), "hostile.zip")
    member = artifact(store, parent["id"], "archive_analysis")["members"][0]
    assert member["suspicious_path"] is True and member["status"] == "analyzed"
    child = store.get_file(member["child_file_id"])
    assert child["storage_id"].startswith("sha256/") and ".." not in child["storage_id"]


def test_tar_regular_and_symlink_are_safe(tmp_path):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        regular = tarfile.TarInfo("regular.txt"); regular.size = 4; archive.addfile(regular, io.BytesIO(b"data"))
        link = tarfile.TarInfo("link"); link.type = tarfile.SYMTYPE; link.linkname = "/etc/passwd"; archive.addfile(link)
    store, objects, case = environment(tmp_path)
    parent = upload(store, objects, case, output.getvalue(), "files.tar")
    members = artifact(store, parent["id"], "archive_analysis")["members"]
    assert members[0]["status"] == "analyzed"
    assert members[1]["special"] is True and members[1]["reason"] == "special_member"


def test_gzip_and_nested_archive(tmp_path):
    nested = zip_bytes([("nested.txt", b"nested")])
    outer = zip_bytes([("inner.zip", nested)])
    store, objects, case = environment(tmp_path)
    parent = upload(store, objects, case, outer, "outer.zip")
    outer_analysis = artifact(store, parent["id"], "archive_analysis")
    child_id = outer_analysis["members"][0]["child_file_id"]
    assert artifact(store, child_id, "archive_analysis")["members"][0]["child_sha256"]
    gz = gzip.compress(b"gzip child", mtime=0)
    gzip_parent = upload(store, objects, case, gz, "child.txt.gz")
    assert artifact(store, gzip_parent["id"], "archive_analysis")["members"][0]["actual_bytes"] == 10


def test_archive_limits(tmp_path):
    cases = [
        (AnalysisLimits(max_members=1), zip_bytes([("a", b"1"), ("b", b"2")]), "max_members"),
        (AnalysisLimits(max_member_bytes=2), zip_bytes([("a", b"123")]), "max_member_bytes"),
        (AnalysisLimits(max_total_bytes=2), zip_bytes([("a", b"123")]), "max_total_bytes"),
        (AnalysisLimits(max_ratio=2), zip_bytes([("a", b"A" * 1000)]), "max_compression_ratio"),
        (AnalysisLimits(max_depth=1), zip_bytes([("inner.zip", zip_bytes([("a", b"1")]))]), "max_depth"),
    ]
    for index, (limits, raw, reason) in enumerate(cases):
        store, objects, case = environment(tmp_path / str(index))
        parent = upload(store, objects, case, raw, "limited.zip", limits)
        if reason == "max_depth":
            child_id = artifact(store, parent["id"], "archive_analysis")["members"][0]["child_file_id"]
            assert artifact(store, child_id, "archive_analysis")["reason"] == reason
        else:
            result = artifact(store, parent["id"], "archive_analysis")
            assert reason == result["reason"] or any(member.get("reason") == reason for member in result["members"])


def test_malformed_and_encrypted_zip(tmp_path):
    store, objects, case = environment(tmp_path)
    malformed = upload(store, objects, case, b"PK\x03\x04truncated", "bad.zip")
    assert artifact(store, malformed["id"], "archive_analysis")["reason"] == "malformed_archive"
    raw = bytearray(zip_bytes([("secret.txt", b"secret")]))
    local = raw.find(b"PK\x03\x04"); central = raw.find(b"PK\x01\x02")
    raw[local + 6:local + 8] = (1).to_bytes(2, "little")
    raw[central + 8:central + 10] = (1).to_bytes(2, "little")
    encrypted = upload(store, objects, case, bytes(raw), "encrypted.zip")
    member = artifact(store, encrypted["id"], "archive_analysis")["members"][0]
    assert member["encrypted"] is True and member["reason"] == "encrypted_member"


def image_bytes(format, size=(3, 2), exif=None):
    output = io.BytesIO()
    options = {"exif": exif} if exif is not None else {}
    Image.new("RGB", size, "red").save(output, format=format, **options)
    return output.getvalue()


@pytest.mark.parametrize("format,name", [("PNG", "x.png"), ("JPEG", "x.jpg"), ("GIF", "x.gif")])
def test_image_dimensions(format, name, tmp_path):
    store, objects, case = environment(tmp_path)
    file = upload(store, objects, case, image_bytes(format), name)
    data = artifact(store, file["id"], "image_metadata")
    assert (data["width"], data["height"], data["format"]) == (3, 2, format)


def test_exif_and_image_limits(tmp_path):
    exif = Image.Exif(); exif[271] = "CameraCo"; exif[272] = "ModelX"; exif[274] = 6
    store, objects, case = environment(tmp_path)
    file = upload(store, objects, case, image_bytes("JPEG", exif=exif), "exif.jpg")
    data = artifact(store, file["id"], "image_metadata")
    assert data["exif"] == {"make": "CameraCo", "model": "ModelX", "orientation": "6"}
    limited = upload(store, objects, case, image_bytes("PNG", (20, 20)), "large.png", AnalysisLimits(max_image_pixels=100))
    assert artifact(store, limited["id"], "image_metadata")["reason"] == "max_image_pixels"
    malformed = upload(store, objects, case, b"\x89PNG\r\n\x1a\ninvalid", "bad.png")
    assert artifact(store, malformed["id"], "image_metadata")["reason"] == "malformed_image"


def test_pdf_metadata_and_active_indicator(tmp_path):
    raw = b"%PDF-1.7\n1 0 obj<</Type /Catalog /OpenAction 2 0 R>>endobj\n2 0 obj<</Type /Page>>endobj\n<</Title (Case) /Author (Analyst) /JavaScript (x)>>\n%%EOF"
    store, objects, case = environment(tmp_path)
    file = upload(store, objects, case, raw, "case.pdf")
    data = artifact(store, file["id"], "pdf_metadata")
    assert data["version"] == "1.7" and data["page_count"] == 1
    assert data["metadata"]["title"] == "Case" and data["javascript_present"] is True
    malformed = upload(store, objects, case, b"%PDF-broken", "bad.pdf")
    assert artifact(store, malformed["id"], "pdf_metadata")["reason"] == "malformed_pdf"


@pytest.mark.parametrize("folder,expected", [("word/document.xml", "docx"), ("xl/workbook.xml", "xlsx"), ("ppt/presentation.xml", "pptx")])
def test_office_metadata_and_safe_malformed_xml(folder, expected, tmp_path):
    core = b'<cp:coreProperties xmlns:cp="x" xmlns:dc="y"><dc:title>Report</dc:title><dc:creator>Alice</dc:creator></cp:coreProperties>'
    raw = zip_bytes([(folder, b"<root/>"), ("docProps/core.xml", core), ("word/vbaProject.bin", b"not executed")])
    store, objects, case = environment(tmp_path)
    file = upload(store, objects, case, raw, expected + ".zip")
    data = artifact(store, file["id"], "document_metadata")
    assert data["format"] == expected and data["metadata"]["title"] == "Report"
    assert data["vba_present"] is True
    malicious = zip_bytes([(folder, b"x"), ("docProps/core.xml", b'<!DOCTYPE x [<!ENTITY e SYSTEM "http://127.0.0.1/">]><x>&e;</x>')])
    bad = upload(store, objects, case, malicious, "bad.docx")
    assert artifact(store, bad["id"], "document_metadata")["malformed_metadata"] is True


def test_odf_metadata(tmp_path):
    meta = b'<office:document-meta xmlns:office="o" xmlns:dc="d"><dc:title>Open Report</dc:title><dc:creator>Bob</dc:creator></office:document-meta>'
    raw = zip_bytes([("mimetype", b"application/vnd.oasis.opendocument.text"), ("meta.xml", meta), ("content.xml", b"<x/>")])
    store, objects, case = environment(tmp_path)
    file = upload(store, objects, case, raw, "report.odt")
    data = artifact(store, file["id"], "document_metadata")
    assert data["format"] == "odt" and data["metadata"]["title"] == "Open Report"
