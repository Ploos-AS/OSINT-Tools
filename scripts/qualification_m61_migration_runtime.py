#!/usr/bin/env python3
"""Real Docker startup/restart of the immutable M6.0 schema-8 fixture."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
from qualification_m61_migration import fixture
from qualification_m61_runtime import Client

def docker(*args): return subprocess.check_output(['docker',*args],stderr=subprocess.STDOUT,text=True).strip()

def main():
    name=f'osint-m61-migration-{os.getpid()}'
    try:
        with tempfile.TemporaryDirectory(prefix='osint-m61-migration-') as temp:
            root=Path(temp); root.chmod(0o755); data=root/'data'; data.mkdir(); data.chmod(0o777)
            for sub in ['files','files/sha256','files/.tmp']:
                directory=data/sub; directory.mkdir(); directory.chmod(0o777)
            db=data/'osint-tools.db'; fixture(db)
            for p in data.iterdir():
                if p.is_file(): p.chmod(0o666)
            try:
                docker('run','-d','--name',name,'-p','127.0.0.1::8080','-e','OSINT_TOOLS_AUTH_ENABLED=true','-v',f'{data}:/data','osint-tools:dev')
                port=docker('port',name,'8080/tcp').rsplit(':',1)[1]; base=f'http://127.0.0.1:{port}'
                def ready():
                    nonlocal_base=docker('port',name,'8080/tcp').rsplit(':',1)[1]
                    current_base=f'http://127.0.0.1:{nonlocal_base}'
                    for _ in range(60):
                        try:
                            with urllib.request.urlopen(current_base+'/healthz',timeout=2) as r: assert r.status==200
                            return current_base
                        except Exception: time.sleep(0.5)
                    raise AssertionError('migration runtime did not start: '+docker('logs','--tail','15',name)[-1500:])
                base=ready()
                admin=Client(base).login('migrationadmin','qualification-migration-sentinel')
                cases=admin.ok('GET','/api/v1/cases'); assert len(cases)==1
                c=cases[0]; assert c['name']=='M61 legacy schema8' and c['owner_user_id'] is None
                assert admin.ok('GET','/api/v1/cases/1')['targets'][0]['normalized']=='legacy.example'
                docker('exec',name,'python','-c',"""
import sqlite3
with sqlite3.connect('/data/osint-tools.db') as conn:
    assert conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0]=='9'
    assert conn.execute("SELECT COUNT(*) FROM sessions WHERE token_hash='fixture-session-hash'").fetchone()[0]==1
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='fixture_preserved'").fetchone()[0]==1
    assert {'teams','team_members','case_acl'} <= {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert conn.execute('PRAGMA foreign_key_check').fetchall()==[]
""")
                admin.ok('POST','/api/v1/admin/users',{'username':'migrationanalyst','password':'qualification-migration-sentinel','role':'analyst'},201)
                analyst=Client(base).login('migrationanalyst','qualification-migration-sentinel')
                assert analyst.ok('GET','/api/v1/cases')==[]
                assert analyst.call('POST','/api/v1/cases/1/claim',{})[0]==404
                payload={'owner_user_id':analyst.uid}; claim='/api/v1/cases/1/claim'; saved=admin.csrf
                assert admin.call('POST',claim,payload,False)[0]==403
                for invalid in ['wrong',analyst.csrf]:
                    admin.csrf=invalid; assert admin.call('POST',claim,payload)[0]==403
                admin.csrf=saved
                assert admin.call('POST',claim+'?csrf_token='+saved,payload,False)[0]==403
                admin.ok('POST',claim,payload,201)
                print('M6.1 legacy adoption CSRF|PASS|missing/wrong/cross-session/query-only rejected; valid succeeds')
                assert analyst.ok('GET','/api/v1/cases/1')['owner_user_id']==analyst.uid
                docker('restart',name); base=ready(); admin.base=base; analyst.base=base
                assert analyst.ok('GET','/api/v1/cases/1')['owner_user_id']==analyst.uid
                assert any(e['action']=='case_claimed' for e in admin.ok('GET','/api/v1/admin/audit'))
                print('M6.1 schema 8 runtime migration|PASS|startup, evidence/users/session/audit, adoption and restart verified')
            finally:
                try: docker('rm','-f',name)
                except subprocess.CalledProcessError: pass
        return 0
    except Exception as exc:
        print(f'M6.1 schema 8 runtime migration|FAIL|{type(exc).__name__}: {str(exc)[:250]}')
        return 1

if __name__=='__main__': raise SystemExit(main())
