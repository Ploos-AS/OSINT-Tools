import importlib.util
import io
import json
import sqlite3
import threading
from pathlib import Path
from http.server import ThreadingHTTPServer
import pytest
from osint_tools.storage import Store
from osint_tools.case_access import (AccessError, effective_case_access, require_case_access, visible_cases, case_admin, teams_api)
from osint_tools.auth import hash_password

@pytest.fixture
def model(tmp_path):
    store=Store(tmp_path/'db')
    users=[store.create_user(n,n,'fixture-not-a-real-password-hash',r) for n,r in [('admin','admin'),('a','analyst'),('b','analyst'),('v','viewer')]]
    case=store.create_case('private',owner_user_id=users[1]['id'])
    return store,users,case

@pytest.mark.parametrize('role,grant,expected',[(r,g,('owner' if r=='admin' else 'viewer' if r=='viewer' else g)) for r in ['admin','analyst','viewer'] for g in ['viewer','editor','owner']])
def test_role_ceiling(model,role,grant,expected):
    s,users,c=model; u=next(x for x in users if x['role']==role)
    with s.connect() as conn:
        conn.execute('UPDATE cases SET owner_user_id=? WHERE id=?',(u['id'] if grant=='owner' else users[2]['id'],c['id']))
        if grant!='owner': conn.execute('INSERT INTO case_acl(case_id,user_id,access) VALUES(?,?,?)',(c['id'],u['id'],grant))
        assert effective_case_access(conn,c['id'],u)==expected

@pytest.mark.parametrize('owner',[None,0,-1,'1',True,99999])
def test_invalid_transfer_owner(model,owner):
    s,u,c=model
    with pytest.raises(AccessError): case_admin(s,u[1],c['id'],'owner',{'owner_user_id':owner})
    assert s.get_case(c['id'])['owner_user_id']==u[1]['id']

def test_disabled_owner_rejected(model):
    s,u,c=model; s.update_user(u[2]['id'],enabled=False)
    with pytest.raises(AccessError): case_admin(s,u[1],c['id'],'owner',{'owner_user_id':u[2]['id']})

@pytest.mark.parametrize('body',[
    {'principal_type':'user','principal_id':999999,'access':'viewer'},
    {'principal_type':'team','principal_id':999999,'access':'editor'},
    {'principal_type':'role','principal_id':1,'access':'viewer'},
    {'principal_type':'user','principal_id':True,'access':'viewer'},
    {'principal_type':'user','principal_id':1,'access':'owner'},
    {'principal_type':'user','principal_id':'1','access':'viewer'}])
def test_invalid_acl_principals(model,body):
    s,u,c=model
    with pytest.raises(AccessError): case_admin(s,u[1],c['id'],'grant',body)

@pytest.mark.parametrize('table,sql',[
    ('case_acl',"INSERT INTO case_acl(case_id,user_id,team_id,access) VALUES(1,1,1,'viewer')"),
    ('case_acl',"INSERT INTO case_acl(case_id,access) VALUES(1,'viewer')"),
    ('case_acl',"INSERT INTO case_acl(case_id,user_id,access) VALUES(1,9999,'viewer')"),
    ('team_members',"INSERT INTO team_members VALUES(9999,1,'now')")])
def test_database_constraints(model,table,sql):
    s,u,c=model
    with pytest.raises(sqlite3.IntegrityError):
        with s.connect() as conn: conn.execute(sql)

def test_legacy_explicit_adoption(model):
    s,u,_=model; c=s.create_case('legacy')
    assert c['owner_user_id'] is None and c['id'] not in [x['id'] for x in visible_cases(s,u[1])]
    with pytest.raises(AccessError): case_admin(s,u[1],c['id'],'claim',{})
    case_admin(s,u[0],c['id'],'claim',{'owner_user_id':u[1]['id']})
    with pytest.raises(AccessError): case_admin(s,u[0],c['id'],'claim',{})
    assert s.get_case(c['id'])['owner_user_id']==u[1]['id']
    assert {'case_claimed','case_owner_changed'} <= {e['action'] for e in s.list_audit()}

def test_owner_does_not_keep_implicit_access(model):
    s,u,c=model; case_admin(s,u[1],c['id'],'owner',{'owner_user_id':u[2]['id']})
    with s.connect() as conn: assert effective_case_access(conn,c['id'],u[1]) is None

def test_strongest_grant_and_live_membership(model):
    s,u,c=model
    team=teams_api(s,u[0],'POST',[],{'name':'team'})
    teams_api(s,u[0],'POST',[str(team['id']),'members'],{'user_id':u[2]['id']})
    case_admin(s,u[1],c['id'],'grant',{'principal_type':'user','principal_id':u[2]['id'],'access':'viewer'})
    case_admin(s,u[1],c['id'],'grant',{'principal_type':'team','principal_id':team['id'],'access':'editor'})
    with s.connect() as conn: assert effective_case_access(conn,c['id'],u[2])=='editor'
    teams_api(s,u[0],'PATCH',[str(team['id'])],{'enabled':False})
    with s.connect() as conn: assert effective_case_access(conn,c['id'],u[2])=='viewer'

def test_auth_disabled_no_fake_users(tmp_path):
    s=Store(tmp_path/'db'); c=s.create_case('legacy')
    with s.connect() as conn: assert require_case_access(conn,c['id'],None,'owner',False)=='owner'
    assert len(visible_cases(s,None,False))==1 and s.count_users()==0

def test_cross_case_note_reference(model):
    s,u,c=model; other=s.create_case('other',owner_user_id=u[2]['id']); t=s.add_target(other['id'],'domain','example.com','example.com')
    with pytest.raises(AccessError): s.add_note(c['id'],'cross',target_id=t['id'])
    assert s.get_case(c['id'])['notes']==[]

def test_schema8_migration_preserves_security_data(tmp_path):
    from scripts.qualification_m61_migration import fixture
    db=tmp_path/'db'; fixture(db); s=Store(db)
    assert s.get_case(1)['name']=='M61 legacy schema8' and s.get_case(1)['owner_user_id'] is None
    assert s.get_user(1)['username']=='migrationadmin'
    assert s.get_session('fixture-session-hash')['user_id']==1
    assert any(e['action']=='fixture_preserved' for e in s.list_audit())
    with s.connect() as conn:
        assert conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0]=='9'
        assert conn.execute('PRAGMA foreign_key_check').fetchall()==[]
        assert conn.execute('PRAGMA journal_mode').fetchone()[0]=='wal'


def test_http_cross_user_security(tmp_path,monkeypatch):
    from osint_tools import server
    from osint_tools.files.store import ContentStore
    from scripts.qualification_m61_runtime import run
    monkeypatch.setattr(server,'AUTH_ENABLED',True)
    monkeypatch.setattr(server,'STORE',Store(tmp_path/'db'))
    monkeypatch.setattr(server,'FILE_STORE',ContentStore(tmp_path/'files'))
    try:
        http=ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
    except PermissionError:
        pytest.skip('local socket binding unavailable; Docker/Podman runtime gate covers HTTP')
    thread=threading.Thread(target=http.serve_forever,daemon=True); thread.start()
    try:
        rows=run(f'http://127.0.0.1:{http.server_port}')
        assert len(rows)>=30
        assert not [r for r in rows if r[1]!='PASS']
    finally: http.shutdown(); http.server_close(); thread.join()

@pytest.mark.parametrize('kind',['native','stix','taxii','misp'])
def test_import_cannot_modify_security_tables(model,tmp_path,kind):
    from osint_tools.export import export_bundle,import_bundle,payload_sha256
    from osint_tools.stix import import_stix
    from osint_tools.misp import import_event
    from osint_tools.files.store import ContentStore
    import zipfile,hashlib
    s,u,c=model; objects=ContentStore(tmp_path/'objects')
    teams_api(s,u[0],'POST',[],{'name':'protected team'})
    s.create_session('protected-hash',u[1]['id'],'protected-csrf-hash','2999-01-01T00:00:00+00:00')
    def snapshot():
        with s.connect() as conn: return {t:[tuple(r) for r in conn.execute(f'SELECT * FROM {t} ORDER BY 1')] for t in ['users','sessions','teams','team_members','case_acl']}
    before=snapshot()
    malicious={'owner_user_id':u[2]['id'],'owner':u[2]['id'],'acl':[{'principal_type':'user','principal_id':u[2]['id'],'access':'editor'}],'teams':[{'id':1,'enabled':False}],'users':[{'id':u[1]['id'],'role':'admin','password_hash':'injected'}],'sessions':[{'token_hash':'injected'}],'auth_config':{'enabled':False},'audit_config':{'enabled':False}}
    if kind=='native':
        raw=export_bundle(s,objects,c['id']); z=zipfile.ZipFile(io.BytesIO(raw)); entries={n:z.read(n) for n in z.namelist()}
        doc=json.loads(entries['case.json']); doc.update(malicious); doc['case'].update(malicious)
        entries['case.json']=json.dumps(doc).encode(); manifest=json.loads(entries['manifest.json']); manifest['canonical_payload_sha256']=payload_sha256(doc)
        for entry in manifest['entries']:
            if entry['path']=='case.json': entry.update(length=len(entries['case.json']),sha256=hashlib.sha256(entries['case.json']).hexdigest())
        entries['manifest.json']=json.dumps(manifest).encode(); stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as out:
            for name,data in entries.items(): out.writestr(name,data)
        result=import_bundle(s,objects,stream.getvalue(),owner_user_id=u[1]['id'])
    elif kind in {'stix','taxii'}:
        result=import_stix(s,json.dumps({'type':'bundle','objects':[],**malicious}).encode(),{'transport':kind},owner_user_id=u[1]['id'])
    else: result=import_event(s,{'Event':{'info':'foreign','Attribute':[],**malicious},**malicious},owner_user_id=u[1]['id'])
    assert snapshot()==before
    assert s.get_case(result['case_id'])['owner_user_id']==u[1]['id']
