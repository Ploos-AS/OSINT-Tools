import json
from osint_tools.storage import Store
from osint_tools.stix import export_stix, import_stix

def test_stix_export_import_and_deterministic_ids(tmp_path):
    s=Store(tmp_path/'db'); c=s.create_case('<script>alert(1)</script>'); d=s.add_target(c['id'],'domain','Example.COM','example.com'); i=s.add_target(c['id'],'ip','192.0.2.1','192.0.2.1'); s.add_relationship(c['id'],d['id'],'resolved_to',i['id'])
    a=export_stix(s,c['id']); b=export_stix(s,c['id']); assert a['type']=='bundle' and a['objects'][1]['id']==b['objects'][1]['id']; assert any(x['type']=='domain-name' for x in a['objects'])
    result=import_stix(s,json.dumps(a).encode()); assert result['case_id'] != c['id']; assert s.get_case(result['case_id'])['targets']
