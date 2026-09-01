import io
import os
import socket
import struct

import pytest

os.environ.setdefault("OSINT_TOOLS_DATA_DIR", "/tmp/osint-tools-test-import")
from osint_tools import server
from osint_tools.av import AVRegistry, ClamAVEngine
from osint_tools.av.base import AVResult
from osint_tools.av.service import AVError, scan_file
from osint_tools.files.service import ingest_file
from osint_tools.files.store import ContentStore
from osint_tools.storage import Store


class FakeSocket:
    def __init__(self, responses): self.responses=list(responses); self.sent=[]
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def settimeout(self,value): self.timeout=value
    def sendall(self,value): self.sent.append(value)
    def recv(self,n): return self.responses.pop(0) if self.responses else b""


def env(tmp_path):
    store=Store(tmp_path/"db"); objects=ContentStore(tmp_path/"files"); case=store.create_case("av")
    return store,objects,case


def test_registry_and_normalized_result_states():
    engine=ClamAVEngine(); registry=AVRegistry([engine]); assert registry.get("clamav") is engine and registry.list()==[engine]
    with pytest.raises(ValueError): registry.register(engine)
    for state in ("clean","detected","error","timeout","unavailable","unsupported","skipped"): assert AVResult("x",None,None,None,state).state==state
    with pytest.raises(ValueError): AVResult("x",None,None,None,"malicious")


def test_clamav_ping_version_and_clean_stream(tmp_path,monkeypatch):
    engine=ClamAVEngine(True)
    # Real clamd uses NUL framing for zINSTREAM (unlike PING/VERSION).
    scan_sock=FakeSocket([b"stream: OK\0"])
    sockets=[FakeSocket([b"PONG\n"]),FakeSocket([b"ClamAV 1.4.3/123:1\n"]),FakeSocket([b"ClamAV 1.4.3/123:1\n"]),scan_sock]
    monkeypatch.setattr(engine,"_connect",lambda timeout:sockets.pop(0))
    status=engine.status(); assert status["available"] and status["engine_version"]=="ClamAV 1.4.3" and status["database_version"]=="123:1"
    path=tmp_path/"x"; path.write_bytes(b"hello")
    result=engine.scan(path,5,"a"*64); assert result.state=="clean" and result.bytes_scanned==5
    assert scan_sock.sent[0]==b"zINSTREAM\0" and scan_sock.sent[-1][-4:]==b"\0\0\0\0"


def test_clamav_detected_malformed_timeout_and_size_limit(tmp_path,monkeypatch):
    path=tmp_path/"x"; path.write_bytes(b"EICAR")
    engine=ClamAVEngine(True)
    def fake_version(timeout,maximum): return "ClamAV 1", "db", "raw"
    monkeypatch.setattr(engine,"_version",fake_version)
    for response,expected in ((b"stream: Eicar-Test-Signature FOUND\0","detected"),(b"nonsense\n","error"),(b"stream: Size limit exceeded ERROR\0","unsupported")):
        sock=FakeSocket([response]); monkeypatch.setattr(engine,"_connect",lambda timeout,s=sock:s); assert engine.scan(path,5,"a"*64).state==expected
    def timeout(*args): raise socket.timeout()
    monkeypatch.setattr(engine,"_version",timeout); assert engine.scan(path,5,"a"*64).state=="timeout"


def test_clamav_disabled_unavailable_and_scan_failure_isolated(tmp_path,monkeypatch):
    store,objects,case=env(tmp_path); file=ingest_file(store,objects,case["id"],io.BytesIO(b"x"),1,"x",10)
    disabled=ClamAVEngine(False); result=scan_file(store,objects,AVRegistry([disabled]),file["id"])[0]; assert result["state"]=="skipped" and result["error_code"]=="disabled"
    unavailable=ClamAVEngine(True)
    monkeypatch.setattr(unavailable,"status",lambda:{"available":False,"status":"unavailable"})
    result=scan_file(store,objects,AVRegistry([unavailable]),file["id"])[0]; assert result["state"]=="unavailable"
    assert store.list_av_results(file["id"])[0]["state"]=="unavailable"
    with pytest.raises(AVError) as caught: scan_file(store,objects,AVRegistry([]),file["id"],["missing"])
    assert caught.value.code=="unknown_engine"


def test_clamav_detection_persistence_idempotency_and_provenance(tmp_path,monkeypatch):
    store,objects,case=env(tmp_path); file=ingest_file(store,objects,case["id"],io.BytesIO(b"x"),1,"x",10)
    engine=ClamAVEngine(True); monkeypatch.setattr(engine,"status",lambda:{"available":True})
    monkeypatch.setattr(engine,"scan",lambda *args: AVResult("clamav","1","db","", "detected", [{"signature":"Test.Signature"}], "now", 2, 1, provenance={"engine":"clamav","engine_version":"1","database_version":"db"}))
    registry=AVRegistry([engine]); first=scan_file(store,objects,registry,file["id"])[0]; second=scan_file(store,objects,registry,file["id"])[0]
    assert first["id"]==second["id"] and second["provenance"]["object_sha256"]==file["sha256"]
    persisted=Store(store.path).list_av_results(file["id"]); assert len(persisted)==1 and persisted[0]["detections"][0]["signature"]=="Test.Signature"


def test_av_api_does_not_accept_destinations(tmp_path,monkeypatch):
    store,objects,case=env(tmp_path); file=ingest_file(store,objects,case["id"],io.BytesIO(b"x"),1,"x",10)
    monkeypatch.setattr(server,"STORE",store); monkeypatch.setattr(server,"FILE_STORE",objects); monkeypatch.setattr(server,"AV_REGISTRY",AVRegistry([ClamAVEngine(False)]))
    instance=object.__new__(server.Handler); instance.path=f"/api/v1/files/{file['id']}/av/scan"; instance._body=lambda *args:{"host":"127.0.0.1","port":1}; captured={}; instance._json=lambda status,payload: captured.update(status=status,payload=payload)
    instance.do_POST(); assert captured["status"]==200 and captured["payload"]["result"][0]["state"]=="skipped"
    assert "host" not in captured["payload"]["result"][0]


def test_av_status_and_result_apis(tmp_path,monkeypatch):
    store,objects,case=env(tmp_path); file=ingest_file(store,objects,case["id"],io.BytesIO(b"x"),1,"x",10)
    engine=ClamAVEngine(False); monkeypatch.setattr(server,"STORE",store); monkeypatch.setattr(server,"FILE_STORE",objects); monkeypatch.setattr(server,"AV_REGISTRY",AVRegistry([engine]))
    for path in ("/api/v1/av/engines", "/api/v1/av/engines/clamav"):
        instance=object.__new__(server.Handler); instance.path=path; captured={}; instance._json=lambda status,payload: captured.update(status=status,payload=payload); instance.do_GET(); assert captured["status"]==200
    instance=object.__new__(server.Handler); instance.path=f"/api/v1/files/{file['id']}/av"; captured={}; instance._json=lambda status,payload: captured.update(status=status,payload=payload); instance.do_GET(); assert captured["status"]==200 and captured["payload"]["result"]["results"]==[]
