import io
import math
import struct
import zipfile

import pytest

from osint_tools.files.amiga_hunk import parse_hunk
from osint_tools.files.binary_common import BinaryLimits, entropy, extract_strings
from osint_tools.files.candidates import promote_candidate
from osint_tools.files.elf import parse_elf
from osint_tools.files.indicators import extract_candidates
from osint_tools.files.macho import parse_macho
from osint_tools.files.pe import parse_pe
from osint_tools.files.service import FileError, ingest_file
from osint_tools.files.store import ContentStore
from osint_tools.storage import Store


LIMITS = BinaryLimits(max_scan_bytes=65536, max_strings=20, max_candidates=20)


def pe_fixture(extra=b"http://Example.com/a contact@Example.com 192.0.2.4"):
    data = bytearray(0x220 + len(extra)); data[:2] = b"MZ"; struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"; struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 1234, 0, 0, 224, 2)
    opt = 0x98; struct.pack_into("<H", data, opt, 0x10B); struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<I", data, opt + 28, 0x400000); struct.pack_into("<H", data, opt + 68, 3)
    sec = opt + 224; data[sec:sec + 8] = b".text\0\0\0"; struct.pack_into("<IIII", data, sec + 8, len(extra), 0x1000, len(extra), 0x200)
    struct.pack_into("<I", data, sec + 36, 0x60000020); data[0x200:] = extra
    return bytes(data)


def elf_fixture():
    data = bytearray(64); data[:6] = b"\x7fELF\x02\x01"; data[6] = 1
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, 0x401000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    return bytes(data)


def macho_fixture():
    return b"\xcf\xfa\xed\xfe" + struct.pack("<IIIIIII", 0x01000007, 3, 2, 0, 0, 0, 0)


def hunk_fixture():
    words = [1011, 0, 1, 0, 0, 2, 1001, 1, 0x41424344, 1010, 1003, 2, 1010]
    return b"".join(struct.pack(">I", word) for word in words)


def test_entropy_and_bounded_ascii_utf16_strings():
    assert entropy(b"\0" * 100) == 0.0
    assert entropy(bytes(range(256))) == 8.0
    values, truncated = extract_strings(b"abc HELLO\0W\x00I\x00D\x00E\x00", BinaryLimits(max_strings=2, min_string_length=4, max_string_length=5))
    assert [item["encoding"] for item in values] == ["ascii", "utf-16le"]
    assert values[0]["value"] == "abc H" and values[0]["truncated"] is True
    assert truncated is True


def test_candidate_types_normalization_offsets_and_limit():
    strings = [{"value": "http://Example.COM/a user@Example.COM 192.0.2.1 2001:db8::1 test.example", "offset": 10, "encoding": "ascii"}]
    values, truncated = extract_candidates(strings, 10)
    assert {value["type"] for value in values} == {"url", "email", "ipv4", "ipv6", "domain"}
    assert all(value["offset"] >= 10 for value in values)
    assert next(value for value in values if value["type"] == "email")["normalized_value"] == "user@example.com"
    assert extract_candidates(strings, 1)[1] is True


@pytest.mark.parametrize("parser,fixture,kind", [(parse_pe, pe_fixture, "pe"), (parse_elf, elf_fixture, "elf"), (parse_macho, macho_fixture, "macho"), (parse_hunk, hunk_fixture, "amiga_hunk")])
def test_formats_and_malformed(parser, fixture, kind):
    result = parser(fixture(), LIMITS)
    assert result["status"] == "success" and result["format"] == kind
    assert parser(fixture()[:12], LIMITS)["status"] == "failed"


def test_pe_elf_macho_and_hunk_metadata():
    pe = parse_pe(pe_fixture(), LIMITS); assert pe["variant"] == "PE32" and pe["architecture"] == "x86" and pe["sections"][0]["name"] == ".text"
    elf = parse_elf(elf_fixture(), LIMITS); assert elf["variant"] == "ELF64" and elf["endianness"] == "little" and elf["architecture"] == "x86_64"
    macho = parse_macho(macho_fixture(), LIMITS); assert macho["bits"] == 64 and macho["architecture"] == "x86_64"
    hunk = parse_hunk(hunk_fixture(), LIMITS); assert hunk["architecture"] == "m68k" and [x["type"] for x in hunk["hunks"]] == ["code", "end", "bss", "end"]
    hostile = struct.pack(">II", 1011, 0xffffffff); assert parse_hunk(hostile, LIMITS)["reason"] == "malformed_hunk"


def test_hunk_relocation_symbol_name_debug_and_external_records():
    words = [1011,0,1,0,0,1,1000,1,0x4e414d45,1001,1,0,1004,1,0,4,0,1007,(129<<24)|1,0x45585400,1,8,0,1008,1,0x53594d00,12,0,1009,1,0,1010]
    result = parse_hunk(b"".join(struct.pack(">I", word) for word in words), LIMITS)
    assert result["status"] == "success" and result["relocation_count"] == 2
    assert result["symbols"][0]["name"] == "SYM" and result["externals"][0]["name"] == "EXT"
    assert result["debug_present"] is True and result["declared_hunks"][0]["memory"] == "any"


def setup(tmp_path):
    store = Store(tmp_path / "db.sqlite"); objects = ContentStore(tmp_path / "files"); case = store.create_case("binary")
    return store, objects, case


def test_binary_artifact_candidates_persistence_and_promotion(tmp_path, monkeypatch):
    store, objects, case = setup(tmp_path); content = pe_fixture()
    file = ingest_file(store, objects, case["id"], io.BytesIO(content), len(content), "not-trusted.txt", len(content), binary_limits=LIMITS)
    analysis = Store(store.path).get_file_analysis(file["id"])
    binary = next(item for item in analysis["structured"] if item["type"] == "binary_analysis")
    assert binary["data"]["structure"]["format"] == "pe"
    candidates = store.list_file_candidates(file["id"])
    assert {item["type"] for item in candidates} >= {"url", "email", "ipv4"}
    url = next(item for item in candidates if item["type"] == "url")
    assert not any(item["type"] == "url" for item in store.get_case(case["id"])["targets"])
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network called")))
    first = promote_candidate(store, file["id"], url["id"]); second = promote_candidate(store, file["id"], url["id"])
    assert first["target"]["id"] == second["target"]["id"]
    assert first["relationship"]["id"] == second["relationship"]["id"]
    assert first["relationship"]["artifact_id"] == binary["id"]
    email = next(item for item in candidates if item["type"] == "email")
    with pytest.raises(FileError) as caught: promote_candidate(store, file["id"], email["id"])
    assert caught.value.code == "candidate_not_promotable"


def test_candidate_analysis_replacement_is_idempotent(tmp_path):
    store, objects, case = setup(tmp_path); content = pe_fixture()
    file = ingest_file(store, objects, case["id"], io.BytesIO(content), len(content), "x", len(content), binary_limits=LIMITS)
    before = store.list_file_candidates(file["id"])
    from osint_tools.files.structured import analyze_structured
    from osint_tools.files.budget import AnalysisLimits
    analyze_structured(store, objects, file, AnalysisLimits(), binary_limits=LIMITS)
    after = store.list_file_candidates(file["id"])
    assert len(after) == len(before)


def test_malformed_binary_does_not_break_baseline(tmp_path):
    store, objects, case = setup(tmp_path); content = b"MZ" + b"x" * 70
    file = ingest_file(store, objects, case["id"], io.BytesIO(content), len(content), "bad.exe", len(content), binary_limits=LIMITS)
    analysis = store.get_file_analysis(file["id"])
    binary = next(item for item in analysis["structured"] if item["type"] == "binary_analysis")
    assert analysis["type"] == "file_analysis" and binary["data"]["status"] == "failed"


def test_binary_child_inside_zip_uses_existing_pipeline(tmp_path):
    store, objects, case = setup(tmp_path); archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped: zipped.writestr("child.exe", pe_fixture())
    content = archive.getvalue()
    parent = ingest_file(store, objects, case["id"], io.BytesIO(content), len(content), "bundle.zip", len(content) + 1, binary_limits=LIMITS)
    graph = store.get_case(case["id"]); contains = next(item for item in graph["relationships"] if item["relation"] == "contains")
    with store.connect() as conn:
        child = conn.execute("SELECT id FROM files WHERE target_id=?", (contains["destination_target_id"],)).fetchone()
    analysis = store.get_file_analysis(child["id"])
    assert any(item["type"] == "binary_analysis" and item["data"]["format"] == "pe" for item in analysis["structured"])
    assert store.list_file_candidates(child["id"])
