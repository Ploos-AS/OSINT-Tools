import io
import os

os.environ.setdefault("OSINT_TOOLS_DATA_DIR", "/tmp/osint-tools-test-import")
from osint_tools import server


def test_scan_on_upload_policy_is_off_by_default_and_opt_in(monkeypatch):
    calls=[]
    monkeypatch.setattr(server,"ingest_file",lambda *args: {"id":7})
    monkeypatch.setattr(server,"scan_file",lambda *args: calls.append(args))
    instance=object.__new__(server.Handler); instance.path="/api/v1/cases/1/files"; instance.headers={"Content-Length":"1","X-Filename":"x"}; instance.rfile=io.BytesIO(b"x"); instance._json=lambda *args: None
    monkeypatch.setattr(server,"AV_SCAN_ON_UPLOAD",False); instance.do_POST(); assert calls==[]
    instance.rfile=io.BytesIO(b"x"); monkeypatch.setattr(server,"AV_SCAN_ON_UPLOAD",True); instance.do_POST(); assert len(calls)==1 and calls[0][3]==7
