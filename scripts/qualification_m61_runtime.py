#!/usr/bin/env python3
"""Actual HTTP case isolation checks, shared by pytest and canonical Docker gates."""
import http.cookiejar
import io
import json
import sys
import urllib.error
import urllib.request
import zipfile
import hashlib

PASSWORD='qualification-m61-password-sentinel'  # Intentional isolated fixture.
class Client:
    def __init__(self,base):
        self.base=base; self.csrf=''; self.uid=None
        self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def call(self,method,path,body=None,token=True):
        headers={'Content-Type':'application/json'}
        if token: headers['X-CSRF-Token']=self.csrf
        data=json.dumps(body).encode() if isinstance(body,(dict,list)) else body
        req=urllib.request.Request(self.base+path,data=data,headers=headers,method=method)
        try: response=self.opener.open(req,timeout=30)
        except urllib.error.HTTPError as exc: response=exc
        with response:
            raw=response.read(); typ=response.headers.get('Content-Type','')
            return response.status,json.loads(raw) if 'json' in typ and raw else raw
    def ok(self,method,path,body=None,status=200):
        got,result=self.call(method,path,body)
        assert got==status, f'{method} {path}: expected {status}, got {got}'
        return result.get('result',result) if isinstance(result,dict) else result
    def login(self,name,password=PASSWORD):
        result=self.ok('POST','/api/v1/auth/login',{'username':name,'password':password})
        self.csrf=result['csrf_token']; self.uid=result['id']; return self

def run(base, *, live=False, persistence=False):
    rows=[]
    def check(name,fn):
        try: fn(); rows.append(('M6.1 '+name,'PASS',''))
        except Exception as exc: rows.append(('M6.1 '+name,'FAIL',str(exc)[:250]))
    def truth(value): assert value
    admin=Client(base)
    if persistence:
        admin.login('m61admin')
        a=Client(base).login('m61a'); b=Client(base).login('m61b')
        check('ACL/team persistence',lambda: truth(any(c['name']=='M61 persistent team case' for c in b.ok('GET','/api/v1/cases')) and any(t['name']=='M61 restored team' for t in admin.ok('GET','/api/v1/admin/teams'))))
        return rows
    bootstrap=admin.call('POST','/api/v1/auth/bootstrap',{'username':'m61admin','password':PASSWORD})[0]
    if bootstrap==409:
        admin.login('admin','qualification-password-sentinel')
        admin.ok('POST','/api/v1/admin/users',{'username':'m61admin','password':PASSWORD,'role':'admin'},201)
    admin.login('m61admin')
    users={}
    for name,role in [('m61a','analyst'),('m61b','analyst'),('m61v','viewer')]:
        users[name]=admin.ok('POST','/api/v1/admin/users',{'username':name,'display_name':'<script>'+name+'</script>','password':PASSWORD,'role':role},201)['id']
    a=Client(base).login('m61a'); b=Client(base).login('m61b'); v=Client(base).login('m61v')
    # A second login deliberately makes the session ID differ from user ID.
    a.login('m61a')
    c=a.ok('POST','/api/v1/cases',{'name':'M61 Case A <script>alert(1)</script>','owner_user_id':b.uid},201); cid=c['id']; path=f'/api/v1/cases/{cid}'
    c2=a.ok('POST','/api/v1/cases',{'name':'M61 persistent team case'},201); p2=f'/api/v1/cases/{c2["id"]}'
    check('version 0.6.1',lambda: truth(admin.ok('GET','/api/v1/info')['version']=='0.6.1'))
    check('owner on case creation',lambda: truth(c['owner_user_id']==a.uid and admin.ok('POST','/api/v1/cases',{'name':'M61 admin case'},201)['owner_user_id']==admin.uid))
    check('inaccessible case listing',lambda: truth(c['id'] not in [x['id'] for x in b.ok('GET','/api/v1/cases')] and 'M61 Case A' not in b.ok('GET','/cases').decode()))
    check('initial cross-user isolation',lambda: truth(b.call('GET',path)[0]==404 and v.call('GET',path)[0]==404 and Client(base).call('GET',path)[0]==401))
    target=a.ok('POST',path+'/targets',{'value':'example.com'},201)['id']
    file=a.ok('POST',path+'/files',b'M61 harmless fixture',201)['id']
    check('target/file authorization confinement',lambda: truth(all(b.call('GET',p)[0]==404 for p in [f'/api/v1/targets/{target}/artifacts',f'/cases/{cid}/targets/{target}',f'/files/{file}']+[f'/api/v1/files/{file}'+s for s in ['','/analysis','/candidates','/detections','/similar','/av']])))
    check('graph/timeline/report/export confinement',lambda: truth(all(b.call('GET',path+'/'+s)[0]==404 for s in ['graph','timeline','report.html','export','bundle','stix','misp'])))
    grant=a.ok('POST',path+'/acl',{'principal_type':'user','principal_id':v.uid,'access':'viewer'},201)
    check('direct ACL viewer',lambda: truth(v.ok('GET',path)['id']==cid and v.call('POST',path+'/notes',{'body':'denied'})[0]==403))
    a.ok('PATCH',path+f'/acl/{grant["id"]}',{'access':'editor'})
    check('viewer global ceiling',lambda: truth(v.call('POST','/api/v1/cases',{'name':'denied'})[0]==403 and v.call('POST',path+'/notes',{'body':'denied'})[0]==403 and v.ok('GET',path+'/access')['effective_access']=='viewer'))
    bg=a.ok('POST',path+'/acl',{'principal_type':'user','principal_id':b.uid,'access':'viewer'},201)
    check('analyst viewer provider ceiling',lambda: truth(b.call('POST',f'/api/v1/targets/{target}/enrich',{})[0]==403))
    check('analyst viewer behavior',lambda: truth(b.call('POST',path+'/notes',{'body':'denied'})[0]==403 and b.call('GET',path+'/acl')[0]==403))
    a.ok('PATCH',path+f'/acl/{bg["id"]}',{'access':'editor'})
    check('analyst editor provider access',lambda: truth(b.call('POST',f'/api/v1/targets/{target}/enrich',{})[0]==200))
    check('direct ACL editor',lambda: truth(b.ok('POST',path+'/notes',{'body':'editor note'},201)['case_id']==cid))
    check('analyst owner/editor behavior',lambda: truth(a.ok('PATCH',path,{'status':'open'})['id']==cid and b.call('PATCH',path,{'name':'denied'})[0]==403 and b.call('POST',path+'/acl',{'principal_type':'user','principal_id':b.uid,'access':'editor'})[0]==403))
    check('malformed principal bounds',lambda: truth(a.call('POST',path+'/acl',{'principal_type':'user','principal_id':10**100,'access':'viewer'})[0]==400))
    check('session identity disclosure boundary',lambda: truth(a.ok('GET','/api/v1/auth/status')['user']['id']==a.uid and all(k not in json.dumps(a.ok('GET','/api/v1/auth/status')) for k in ['token_hash','csrf_hash','password_hash'])))
    check('duplicate ACL conflict',lambda: truth(a.call('POST',path+'/acl',{'principal_type':'user','principal_id':b.uid,'access':'viewer'})[0]==409))
    a.ok('DELETE',path+f'/acl/{bg["id"]}')
    check('ACL revoke',lambda: truth(b.call('GET',path)[0]==404))
    team=admin.ok('POST','/api/v1/admin/teams',{'name':'<script>M61 team</script>','description':'<img src=x onerror=alert(1)>'},201); tp=f'/api/v1/admin/teams/{team["id"]}'
    admin.ok('POST',tp+'/members',{'user_id':b.uid},201)
    tg=a.ok('POST',p2+'/acl',{'principal_type':'team','principal_id':team['id'],'access':'viewer'},201)
    check('team viewer ACL',lambda: truth(b.ok('GET',p2+'/access')['effective_access']=='viewer' and b.call('POST',p2+'/notes',{'body':'denied'})[0]==403))
    a.ok('PATCH',p2+f'/acl/{tg["id"]}',{'access':'editor'})
    check('team editor ACL',lambda: truth(b.ok('POST',p2+'/notes',{'body':'team editor'},201)['case_id']==c2['id']))
    admin.ok('DELETE',tp+f'/members/{b.uid}')
    check('team membership removal',lambda: truth(b.call('GET',p2)[0]==404))
    admin.ok('POST',tp+'/members',{'user_id':b.uid},201)
    check('team membership restoration',lambda: truth(b.ok('GET',p2+'/access')['effective_access']=='editor'))
    admin.ok('PATCH',tp,{'enabled':False})
    check('disabled team',lambda: truth(b.call('GET',p2)[0]==404))
    admin.ok('PATCH',tp,{'enabled':True})
    admin.ok('PATCH',f'/api/v1/admin/users/{b.uid}',{'enabled':False})
    check('disabled user',lambda: truth(b.call('GET',p2)[0]==401))
    admin.ok('PATCH',f'/api/v1/admin/users/{b.uid}',{'enabled':True})
    check('enabled user restoration',lambda: truth(b.ok('GET',p2)['id']==c2['id']))
    check('admin override',lambda: truth(admin.ok('GET',path+'/access')['admin_override'] and admin.ok('PATCH',p2,{'status':'open'})['id']==c2['id']))
    check('admin-only teams',lambda: truth(all(x.call('GET',tp)[0]==403 and x.call('POST',tp+'/members',{'user_id':v.uid})[0]==403 for x in [a,b,v])))
    def csrf(client,method,p,body):
        saved=client.csrf
        try:
            assert client.call(method,p,body,False)[0]==403
            for wrong in ['wrong',v.csrf]:
                client.csrf=wrong; assert client.call(method,p,body)[0]==403
            client.csrf=saved
            assert client.call(method,p+'?csrf_token='+saved,body,False)[0]==403
        finally: client.csrf=saved
    check('ACL CSRF',lambda: csrf(a,'POST',path+'/acl',{'principal_type':'user','principal_id':b.uid,'access':'editor'}))
    check('team CSRF',lambda: csrf(admin,'PATCH',tp,{'name':'forbidden'}))
    check('ACL change/revoke CSRF',lambda: [csrf(a,method,path+f'/acl/{grant["id"]}',{'access':'viewer'} if method=='PATCH' else None) for method in ['PATCH','DELETE']])
    check('team create/membership CSRF',lambda: [csrf(admin,method,p,body) for method,p,body in [('POST','/api/v1/admin/teams',{'name':'denied'}),('POST',tp+'/members',{'user_id':v.uid}),('DELETE',tp+f'/members/{b.uid}',None)]])
    check('ownership CSRF',lambda: csrf(a,'PATCH',path+'/owner',{'owner_user_id':b.uid}))
    admin.ok('PATCH',f'/api/v1/admin/users/{b.uid}',{'enabled':False})
    check('disabled ownership target',lambda: truth(a.call('PATCH',path+'/owner',{'owner_user_id':b.uid})[0]==400))
    admin.ok('PATCH',f'/api/v1/admin/users/{b.uid}',{'enabled':True})
    check('ownership invalid targets',lambda: truth(a.call('PATCH',path+'/owner',{'owner_user_id':v.uid})[0]==400 and a.call('PATCH',path+'/owner',{'owner_user_id':999999})[0]==404))
    check('authenticated ACL/team XSS',lambda: truth('<script>M61 team</script>' not in admin.ok('GET','/admin/teams').decode() and '&lt;script&gt;M61 team&lt;/script&gt;' in a.ok('GET',f'/cases/{c2["id"]}').decode() and '<script>alert(1)</script>' not in a.ok('GET',f'/cases/{cid}').decode()))
    check('access-aware read-only UI',lambda: truth('method="post"' not in v.ok('GET',f'/cases/{cid}').decode() and 'method="post"' not in v.ok('GET',f'/files/{file}').decode()))
    check('provider case ACL',lambda: truth(b.call('POST',f'/api/v1/targets/{target}/enrich',{})[0]==404 and v.call('POST',f'/api/v1/targets/{target}/enrich',{})[0]==403 and a.call('POST',f'/api/v1/targets/{target}/enrich',{})[0]==200))
    if live:
        def av():
            assert b.call('GET',f'/api/v1/files/{file}/av')[0]==404
            assert v.ok('GET',f'/api/v1/files/{file}/av')['file_id']==file
            assert v.call('POST',f'/api/v1/files/{file}/av/scan',{'engines':['clamav']})[0]==403
            assert a.ok('POST',f'/api/v1/files/{file}/av/scan',{'engines':['clamav']})[0]['state']=='clean'
            ag=a.ok('POST',path+'/acl',{'principal_type':'user','principal_id':b.uid,'access':'viewer'},201)
            assert b.call('POST',f'/api/v1/files/{file}/av/scan',{'engines':['clamav']})[0]==403
            a.ok('PATCH',path+f'/acl/{ag["id"]}',{'access':'editor'})
            assert b.ok('POST',f'/api/v1/files/{file}/av/scan',{'engines':['clamav']})[0]['state']=='clean'
            assert b.ok('POST',f'/api/v1/targets/{target}/enrich',{}) is not None
            a.ok('DELETE',path+f'/acl/{ag["id"]}')
            events=admin.ok('GET','/api/v1/admin/audit?limit=200')
            assert {a.uid,b.uid} <= {e['actor_user_id'] for e in events if e['action']=='av_scan' and e['object_id']==str(file)}
        check('real ClamAV case ACL',av)
    forbidden={'owner_user_id':b.uid,'owner':b.uid,'acl':[{'principal_type':'user','principal_id':b.uid,'access':'editor'}],'teams':[{'name':'injected'}],'roles':['admin'],'users':[{'username':'injected'}],'sessions':['injected'],'auth_config':{'enabled':False}}
    before_users=admin.ok('GET','/api/v1/admin/users'); before_teams=admin.ok('GET','/api/v1/admin/teams')
    def imported(p,doc):
        result=a.ok('POST',p,doc,201); new=result['case_id']; result=a.ok('GET',f'/api/v1/cases/{new}')
        assert result['owner_user_id']==a.uid and b.call('GET',f'/api/v1/cases/{new}')[0]==404
        assert a.ok('GET',f'/api/v1/cases/{new}/acl')==[]
    stix={'type':'bundle','objects':[],**forbidden}
    check('STIX import ownership',lambda: imported('/api/v1/cases/import/stix',stix))
    check('MISP import ownership',lambda: imported('/api/v1/cases/import/misp',{'Event':{'info':'foreign','Attribute':[],**forbidden},**forbidden}))
    def native():
        raw=a.ok('GET',path+'/bundle'); z=zipfile.ZipFile(io.BytesIO(raw)); contents={n:z.read(n) for n in z.namelist()}
        payload=json.loads(contents['case.json']); payload.update(forbidden); payload['case'].update(forbidden)
        contents['case.json']=json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        from osint_tools.export import payload_sha256
        manifest=json.loads(contents['manifest.json']); manifest['canonical_payload_sha256']=payload_sha256(payload)
        for entry in manifest['entries']:
            if entry['path']=='case.json': entry.update(length=len(contents['case.json']),sha256=hashlib.sha256(contents['case.json']).hexdigest())
        contents['manifest.json']=json.dumps(manifest).encode(); out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as dest:
            for name,data in contents.items(): dest.writestr(name,data)
        imported('/api/v1/cases/import',out.getvalue())
    check('native import ownership',native)
    if live:
        check('TAXII import ownership',lambda: imported('/api/v1/intelligence/sources/taxii/import',{'collection':'fixture','limit':10,**forbidden}))
        check('remote MISP import ownership',lambda: imported('/api/v1/intelligence/sources/misp/import',{'event':'fixture',**forbidden}))
    check('import authorization isolation',lambda: truth(admin.ok('GET','/api/v1/admin/users')==before_users and admin.ok('GET','/api/v1/admin/teams')==before_teams and a.ok('GET',p2+'/acl')[0]['principal_id']==team['id']))
    def exports():
        for suffix in ['export','stix','misp','report.html']:
            doc=a.ok('GET',path+'/'+suffix); text=json.dumps(doc) if isinstance(doc,(dict,list)) else doc.decode()
            assert all(key not in text for key in ['owner_user_id','case_acl','team_members','password_hash','csrf_hash','token_hash',PASSWORD,a.csrf])
    check('export authorization isolation',exports)
    other=b.ok('POST','/api/v1/cases',{'name':'M61 B private'},201)
    other_target=b.ok('POST',f'/api/v1/cases/{other["id"]}/targets',{'value':'private.example'},201)['id']
    other_file=b.ok('POST',f'/api/v1/cases/{other["id"]}/files',b'M61 harmless fixture',201)['id']
    check('cross-case note confinement',lambda: truth(a.call('POST',path+'/notes',{'body':'denied reference','target_id':other_target})[0]==404))
    check('similarity confinement',lambda: truth(other_file not in [r['file_id'] for r in a.ok('GET',f'/api/v1/files/{file}/similar')] and other_file in [r['file_id'] for r in admin.ok('GET',f'/api/v1/files/{file}/similar')]))
    a.ok('PATCH',path+'/owner',{'owner_user_id':b.uid})
    check('ownership transfer',lambda: truth(b.ok('GET',path)['owner_user_id']==b.uid and a.call('GET',path)[0]==404 and b.ok('GET',path+'/access')['effective_access']=='owner'))
    admin.ok('PATCH',f'/api/v1/admin/users/{b.uid}',{'role':'viewer'})
    check('global viewer owner ceiling',lambda: truth(b.ok('GET',path+'/access')['effective_access']=='viewer' and b.call('PATCH',path,{'name':'denied'})[0]==403 and b.call('POST',path+'/acl',{'principal_type':'user','principal_id':a.uid,'access':'editor'})[0]==403))
    admin.ok('PATCH',f'/api/v1/admin/users/{b.uid}',{'role':'analyst'})
    admin.ok('PATCH',tp,{'name':'M61 restored team'})
    def audits():
        events=admin.ok('GET','/api/v1/admin/audit?limit=200'); actions={e['action'] for e in events}
        assert {'case_created','case_owner_changed','case_acl_granted','case_acl_changed','case_acl_revoked','team_created','team_updated','team_enabled','team_disabled','team_member_added','team_member_removed'} <= actions
        transfer=next(e for e in events if e['action']=='case_owner_changed' and e['metadata']['case_id']==cid)
        assert transfer['actor_user_id']==a.uid and transfer['metadata']['old_owner_user_id']==a.uid and transfer['metadata']['new_owner_user_id']==b.uid
    check('audit',audits)
    check('audit secret redaction',lambda: truth(all(s not in json.dumps(admin.ok('GET','/api/v1/admin/audit?limit=200')) for s in [PASSWORD,a.csrf,b.csrf,v.csrf,'qualification-taxii-sentinel','qualification-misp-sentinel'])))
    return rows

if __name__=='__main__':
    try: results=run(sys.argv[1],live='smoke' not in sys.argv[2:],persistence='persistence' in sys.argv[2:])
    except Exception as exc: results=[('M6.1 runtime setup','FAIL',str(exc)[:250])]
    for name,status,detail in results: print(f'{name}|{status}|{detail}')
    sys.exit(any(status=='FAIL' for _,status,_ in results))
