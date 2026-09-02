import hashlib, io, json, zipfile
from osint_tools.storage import Store
from osint_tools.files.store import ContentStore
from osint_tools.export import canonical_case, export_bundle, export_json, import_bundle, payload_sha256, report_html

def make_case(tmp_path):
    s=Store(tmp_path/'db'); o=ContentStore(tmp_path/'files'); c=s.create_case('<script>alert(1)</script>','secret note')
    a=s.add_target(c['id'],'domain','Example.COM','example.com'); b=s.add_target(c['id'],'ip','1.1.1.1','1.1.1.1'); art=s.add_artifact(c['id'],a['id'],'dns','local',{'answer':'1.1.1.1'}); s.add_relationship(c['id'],a['id'],'resolved_to',b['id'],art['id']); s.add_note(c['id'],'<img src=x onerror=alert(1)>')
    data=o.ingest(io.BytesIO(b'hello'),5,100); f=s.add_file_ingestion(c['id'],'../../secret.txt',{'size':5,'hashes':data['hashes'],'storage_id':data['storage_id'],'detected_type':'text','mime_type':'text/plain','extension':'.txt','ingested_at':'2024-01-01T00:00:00+00:00'})
    return s,o,c,f

def test_export_is_deterministic_and_redactable(tmp_path):
    s,o,c,f=make_case(tmp_path); a=canonical_case(s,c['id']); b=canonical_case(s,c['id']); assert payload_sha256(a)==payload_sha256(b)
    red=canonical_case(s,c['id'],'analyst-safe'); assert 'secret note' not in json.dumps(red) and '[REDACTED: note]' in json.dumps(red)
    assert b'absolute' not in export_json(s,c['id'])

def test_bundle_manifest_integrity_and_metadata_only(tmp_path):
    s,o,c,f=make_case(tmp_path); raw=export_bundle(s,o,c['id']); z=zipfile.ZipFile(io.BytesIO(raw)); m=json.loads(z.read('manifest.json')); assert 'case.json' in z.namelist() and 'files/'+f['sha256'] in z.namelist(); assert m['canonical_payload_sha256']
    meta=zipfile.ZipFile(io.BytesIO(export_bundle(s,o,c['id'],include_bodies=False))); assert not any(n.startswith('files/') for n in meta.namelist())

def test_import_remaps_and_rejects_tampering(tmp_path):
    s,o,c,f=make_case(tmp_path); raw=export_bundle(s,o,c['id']); imported=import_bundle(s,o,raw); assert imported['case_id'] != c['id']; assert s.get_case(imported['case_id'])
    z=zipfile.ZipFile(io.BytesIO(raw)); out=io.BytesIO();
    with zipfile.ZipFile(out,'w') as w:
        for n in z.namelist(): w.writestr(n, b'tampered' if n=='case.json' else z.read(n))
    try: import_bundle(s,o,out.getvalue()); assert False
    except ValueError: pass

def test_report_escapes_and_preserves_evidence_semantics(tmp_path):
    s,o,c,f=make_case(tmp_path); html=report_html(canonical_case(s,c['id'])); text=html.decode(); assert '&lt;script&gt;' in text and 'No universal risk verdict' in text and 'secret note' in text
