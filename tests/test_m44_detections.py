import hashlib
import io
import socket
import sqlite3
import zipfile

import pytest

from osint_tools.files.detections import DetectionLimits, analyze_detections, import_hashset, import_rule_pack, similar_files
from osint_tools.files.hashsets import HashSetError
from osint_tools.files.service import ingest_file
from osint_tools.files.similarity import distance, fingerprint
from osint_tools.files.store import ContentStore
from osint_tools.files.yara_engine import RuleError, YaraLimits, compile_rules, match_rules
from osint_tools.storage import Store


RULES='''rule Demo : harmless test {
 meta: title = "Demo rule" owner = "local"
 strings:
  $a = "MATCH_ME" ascii
  $b = "WIDE" wide
 condition: any of them
}
rule NoMatch { strings: $x = "ABSENT" condition: all of them }
'''


def env(tmp_path):
    store=Store(tmp_path/"db"); objects=ContentStore(tmp_path/"files"); case=store.create_case("m44")
    limits=DetectionLimits(yara=YaraLimits(timeout_seconds=2,max_matches=10,max_string_matches=2),similar_max_results=10,max_scan_bytes=1024*1024)
    return store,objects,case,limits


def upload(store,objects,case,content,name="fixture.bin",limits=None):
    return ingest_file(store,objects,case["id"],io.BytesIO(content),len(content),name,max(len(content),1),detection_limits=limits)


def test_yara_compatible_compilation_match_nonmatch_metadata_and_limits():
    limits=YaraLimits(timeout_seconds=2,max_matches=1,max_string_matches=1)
    compiled=compile_rules(RULES,limits); assert len(compiled)==2 and compiled[0]["tags"]==["harmless","test"]
    status,matches,truncated=match_rules(b"MATCH_ME MATCH_ME",compiled,limits)
    assert status=="success" and len(matches)==1 and matches[0]["metadata"]["title"]=="Demo rule"
    assert len(matches[0]["string_matches"])==1 and truncated is True
    assert match_rules(b"nothing",compiled,limits)[1]==[]


def test_yara_malformed_size_and_deterministic_timeout():
    with pytest.raises(RuleError): compile_rules("rule broken { condition: true }",YaraLimits())
    with pytest.raises(RuleError): compile_rules(RULES,YaraLimits(max_pack_bytes=5))
    status,_,truncated=match_rules(b"MATCH_ME",compile_rules(RULES,YaraLimits()),YaraLimits(timeout_seconds=0))
    assert status=="timeout" and truncated is True


def test_rule_pack_provenance_and_immutable_version(tmp_path):
    store,_,_,limits=env(tmp_path)
    pack=import_rule_pack(store,{"name":"local","version":"1","namespace":"tests","source":"operator","rules":RULES},limits)
    assert pack["rules_sha256"]==hashlib.sha256(RULES.encode()).hexdigest()
    with pytest.raises(RuleError): import_rule_pack(store,{"name":"local","version":"1","namespace":"tests","rules":RULES.replace("MATCH_ME","OTHER")},limits)
    assert len(store.list_rule_packs())==1


@pytest.mark.parametrize("algorithm",["md5","sha1","sha256"])
def test_known_hash_algorithms_categories_and_provenance(tmp_path,algorithm):
    store,objects,case,limits=env(tmp_path); content=b"known content"; digest=hashlib.new(algorithm,content).hexdigest()
    imported=import_hashset(store,{"name":f"set-{algorithm}","version":"1","source":"tests","category":"known_good" if algorithm=="sha256" else "known_bad","entries":[{"algorithm":algorithm,"digest":digest,"label":"fixture","tags":["test"]}]},limits)
    file=upload(store,objects,case,content,limits=limits); matches=store.list_file_detections(file["id"])
    match=next(item for item in matches if item["method"]=="known_hash")
    assert match["metadata"]["algorithm"]==algorithm and match["provenance"]["hash_set_id"]==imported["id"]
    assert match["metadata"]["category"] in {"known_good","known_bad"}


def test_hashset_atomic_malformed_and_dedup(tmp_path):
    store,_,_,limits=env(tmp_path); good="0"*64
    payload={"name":"atomic","version":"1","category":"reference","entries":[{"algorithm":"sha256","digest":good},{"algorithm":"sha256","digest":good}]}
    result=import_hashset(store,payload,limits); assert result["entry_count"]==1
    with pytest.raises(HashSetError): import_hashset(store,{**payload,"entries":[{"algorithm":"sha256","digest":"1"*64}]},limits)
    with pytest.raises(HashSetError): import_hashset(store,{"name":"bad","version":"1","entries":[{"algorithm":"sha256","digest":"xyz"}]},limits)
    assert {item["name"] for item in store.list_hash_sets()}=={"atomic"}


def test_similarity_fingerprint_native_distance_search_bounds_and_order(tmp_path):
    assert distance(fingerprint(b"same"),fingerprint(b"same"))==0
    store,objects,case,limits=env(tmp_path)
    first=upload(store,objects,case,b"A stable body with many common words 1234",limits=limits)
    duplicate=upload(store,objects,case,b"A stable body with many common words 1234","duplicate",limits)
    near=upload(store,objects,case,b"A stable body with many common words 1235","near",limits)
    unrelated=upload(store,objects,case,bytes(range(100)),"other",limits)
    results=similar_files(store,first["id"],2,limits.similar_max_results)
    assert len(results)==2 and results[0]["file_id"]==duplicate["id"] and results[0]["exact_duplicate"] and results[0]["distance"]==0
    assert results[1]["file_id"]==near["id"] and 0 < results[1]["distance"] < 64
    assert distance(store.get_fingerprint(first["sha256"],"simhash64-v1")["fingerprint"],store.get_fingerprint(unrelated["sha256"],"simhash64-v1")["fingerprint"]) >= results[1]["distance"]


def test_detection_reanalysis_idempotency_offline_and_no_targets(tmp_path,monkeypatch):
    store,objects,case,limits=env(tmp_path); import_rule_pack(store,{"name":"test","version":"1","namespace":"tests","rules":RULES},limits)
    monkeypatch.setattr(socket,"getaddrinfo",lambda *a,**k: (_ for _ in ()).throw(AssertionError("network called")))
    file=upload(store,objects,case,b"MATCH_ME",limits=limits); before=store.list_file_detections(file["id"])
    assert next(item for item in before if item["method"]=="yara")["provenance"]["rule_pack_version"]=="1"
    first=analyze_detections(store,objects,file,limits); second=analyze_detections(store,objects,file,limits)
    assert len(store.list_file_detections(file["id"]))==len(before) and first["data"]==second["data"]
    assert len(store.get_case(case["id"])["targets"])==1


def test_archive_child_detection_and_restart_persistence(tmp_path):
    store,objects,case,limits=env(tmp_path); archive=io.BytesIO()
    with zipfile.ZipFile(archive,"w") as zipped: zipped.writestr("child.bin",b"OSINT_TOOLS_DEMO_SIGNATURE")
    parent=upload(store,objects,case,archive.getvalue(),"bundle.zip",limits)
    relation=next(item for item in store.get_case(case["id"])["relationships"] if item["relation"]=="contains")
    with store.connect() as conn: child=conn.execute("SELECT id FROM files WHERE target_id=?",(relation["destination_target_id"],)).fetchone()[0]
    reopened=Store(store.path); detections=reopened.list_file_detections(child)
    assert any(item["signature_id"]=="OSINT_Tools_Harmless_Demo" for item in detections)
    assert reopened.get_fingerprint(reopened.get_file(child)["sha256"],"simhash64-v1") is not None


def test_schema_five_migrates_to_six(tmp_path):
    path=tmp_path/"schema5.db"; store=Store(path); case=store.create_case("preserved")
    with store.connect() as conn:
        for table in ("file_detections","file_fingerprints","hash_entries","hash_sets","rule_packs"): conn.execute(f"DROP TABLE {table}")
        conn.execute("UPDATE schema_meta SET value='5' WHERE key='schema_version'")
    migrated=Store(path); assert migrated.get_case(case["id"])["name"]=="preserved"
    with migrated.connect() as conn:
        assert conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0]=="7"
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='file_detections'").fetchone()
