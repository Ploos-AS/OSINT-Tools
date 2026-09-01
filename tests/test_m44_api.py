import hashlib
import io
import os

os.environ.setdefault("OSINT_TOOLS_DATA_DIR","/tmp/osint-tools-test-import")
from osint_tools import server
from osint_tools.files.detections import DetectionLimits
from osint_tools.files.service import ingest_file
from osint_tools.files.store import ContentStore
from osint_tools.storage import Store


def handler(path,body=None):
    instance=object.__new__(server.Handler); instance.path=path; instance._body=lambda *args: body or {}; captured={}
    instance._json=lambda status,payload: captured.update(status=status,payload=payload) or payload
    return instance,captured


def test_signature_import_detection_similarity_and_reanalysis_apis(tmp_path,monkeypatch):
    store=Store(tmp_path/"db"); objects=ContentStore(tmp_path/"files"); case=store.create_case("api"); limits=DetectionLimits()
    monkeypatch.setattr(server,"STORE",store); monkeypatch.setattr(server,"FILE_STORE",objects); monkeypatch.setattr(server,"DETECTION_LIMITS",limits)
    rules='rule ApiRule { strings: $a = "API_MATCH" condition: any of them }'
    request,out=handler("/api/v1/signatures/rulepacks",{"name":"api","version":"1","namespace":"tests","rules":rules}); request.do_POST(); assert out["status"]==201
    content=b"API_MATCH local fixture"; digest=hashlib.sha256(content).hexdigest()
    request,out=handler("/api/v1/signatures/hashsets",{"name":"hashes","version":"1","category":"reference","entries":[{"algorithm":"sha256","digest":digest}]}); request.do_POST(); assert out["status"]==201
    first=ingest_file(store,objects,case["id"],io.BytesIO(content),len(content),"one",100,detection_limits=limits)
    ingest_file(store,objects,case["id"],io.BytesIO(content+b"!"),len(content)+1,"two",100,detection_limits=limits)
    request,out=handler(f'/api/v1/files/{first["id"]}/detections'); request.do_GET(); assert out["status"]==200 and {x["method"] for x in out["payload"]["result"]}=={"yara","known_hash"}
    request,out=handler(f'/api/v1/files/{first["id"]}/similar?limit=1'); request.do_GET(); assert out["status"]==200 and len(out["payload"]["result"])==1
    request,out=handler(f'/api/v1/files/{first["id"]}/detections/reanalyze',{}); request.do_POST(); assert out["status"]==200
    request,out=handler('/api/v1/signatures/rulepacks'); request.do_GET(); assert out["status"]==200
    request,out=handler('/api/v1/signatures/hashsets'); request.do_GET(); assert out["status"]==200


def test_malformed_signature_material_api_is_structured(tmp_path,monkeypatch):
    monkeypatch.setattr(server,"STORE",Store(tmp_path/"db"))
    request,out=handler("/api/v1/signatures/rulepacks",{"name":"bad","version":"1","namespace":"x","rules":"broken"}); request.do_POST()
    assert out["status"]==422 and out["payload"]["error"]["code"]=="invalid_signature_material"
