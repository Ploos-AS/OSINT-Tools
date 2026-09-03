import json
from osint_tools.storage import Store
from osint_tools.misp import export_event, import_event
from osint_tools.intelligence import SourceRegistry, Source, _validate_url, SourceError

def test_misp_conservative_export_and_import(tmp_path):
    s=Store(tmp_path/'db'); c=s.create_case('<script>alert(1)</script>'); t=s.add_target(c['id'],'domain','Example.COM','example.com'); doc=export_event(s,c['id']); assert doc['Event']['published'] is False; assert doc['Event']['Attribute'][0]['to_ids'] is False
    out=import_event(s,json.loads(json.dumps(doc))); assert out['case_id'] != c['id']

def test_source_status_and_url_boundary():
    src=Source('x','taxii','https://example.test/api',True,token='sentinel'); assert src.status()['hostname']=='example.test' and 'sentinel' not in json.dumps(src.status())
    try: _validate_url('file:///etc/passwd'); assert False
    except SourceError: pass
