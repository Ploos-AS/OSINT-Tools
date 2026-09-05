"""Case authorization: enabled identity, admin override, strongest grant, RBAC ceiling.

NULL-owned legacy cases are admin-only until explicit assignment. Decisions use
fresh database state, never session-cached membership or mutable usernames.
"""
from __future__ import annotations
import json
from .storage import utcnow

LEVELS = {None: 0, 'viewer': 1, 'editor': 2, 'owner': 3}

class AccessError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message
        super().__init__(message)

def identity(conn, user):
    if not user: return None
    return conn.execute('SELECT id,role,enabled FROM users WHERE id=?', (user['id'],)).fetchone()

def effective_case_access(conn, case_id, user, auth_enabled=True):
    case = conn.execute('SELECT owner_user_id FROM cases WHERE id=?', (case_id,)).fetchone()
    if case is None: return None
    if not auth_enabled: return 'owner'
    u = identity(conn, user)
    if not u or not u['enabled']: return None
    if u['role'] == 'admin': return 'owner'
    if case['owner_user_id'] is None: return None
    level = 3 if case['owner_user_id'] == u['id'] else 0
    rows = conn.execute('''SELECT a.access FROM case_acl a WHERE a.case_id=? AND
        (a.user_id=? OR a.team_id IN (SELECT t.id FROM teams t JOIN team_members m
        ON m.team_id=t.id WHERE t.enabled=1 AND m.user_id=?))''', (case_id,u['id'],u['id']))
    level = max([level] + [LEVELS[r['access']] for r in rows])
    if u['role'] == 'viewer': level = min(level, 1)
    return {0:None,1:'viewer',2:'editor',3:'owner'}[level]

def require_case_access(conn, case_id, user, required='viewer', auth_enabled=True):
    access = effective_case_access(conn,case_id,user,auth_enabled)
    if access is None: raise AccessError(404,'not found')
    if LEVELS[access] < LEVELS[required]: raise AccessError(403,'insufficient case access')
    return access

def visible_cases(store, user, auth_enabled=True):
    with store.connect() as conn:
        if not auth_enabled: return [dict(r) for r in conn.execute('SELECT * FROM cases ORDER BY id DESC')]
        u=identity(conn,user)
        if not u or not u['enabled']: return []
        if u['role']=='admin': return [dict(r) for r in conn.execute('SELECT * FROM cases ORDER BY id DESC')]
        return [dict(r) for r in conn.execute('''SELECT c.* FROM cases c WHERE c.owner_user_id IS NOT NULL AND
            (c.owner_user_id=? OR EXISTS(SELECT 1 FROM case_acl a WHERE a.case_id=c.id AND
            (a.user_id=? OR a.team_id IN (SELECT t.id FROM teams t JOIN team_members m ON m.team_id=t.id
            WHERE t.enabled=1 AND m.user_id=?)))) ORDER BY c.id DESC''',(u['id'],u['id'],u['id']))]

def validate_owner(conn, user_id):
    if type(user_id) is not int or user_id <= 0: raise AccessError(400,'invalid owner user ID')
    u=conn.execute('SELECT enabled,role FROM users WHERE id=?',(user_id,)).fetchone()
    if not u: raise AccessError(404,'user not found')
    if not u['enabled'] or u['role'] not in {'analyst','admin'}: raise AccessError(400,'owner must be an enabled analyst or admin')

def audit(conn, action, actor, metadata):
    conn.execute('''INSERT INTO audit_events(timestamp,actor_user_id,action,object_type,object_id,outcome,metadata_json)
        VALUES(?,?,?,?,?,'success',?)''',(utcnow(),actor or None,action,'case' if 'case_id' in metadata else 'team',
        str(metadata.get('case_id',metadata.get('team_id',''))),json.dumps(metadata,sort_keys=True)))

def acl_rows(conn, case_id):
    return [dict(r) for r in conn.execute('''SELECT a.id,a.case_id,
        CASE WHEN a.user_id IS NOT NULL THEN 'user' ELSE 'team' END principal_type,
        COALESCE(a.user_id,a.team_id) principal_id,a.access,
        COALESCE(u.display_name,t.name) display_name FROM case_acl a
        LEFT JOIN users u ON u.id=a.user_id LEFT JOIN teams t ON t.id=a.team_id
        WHERE a.case_id=? ORDER BY a.id''',(case_id,))]

def case_admin(store, user, case_id, action, body, acl_id=None, auth_enabled=True):
    with store.connect() as conn:
        conn.execute('BEGIN IMMEDIATE')
        require_case_access(conn,case_id,user,'owner',auth_enabled)
        actor=user['id'] or None
        if action in {'owner','claim'}:
            if action=='claim':
                u=identity(conn,user)
                if auth_enabled and (not u or u['role']!='admin'): raise AccessError(403,'administrator required')
            old=conn.execute('SELECT owner_user_id FROM cases WHERE id=?',(case_id,)).fetchone()[0]
            if action=='claim' and old is not None: raise AccessError(409,'case already owned')
            new=body.get('owner_user_id',actor); validate_owner(conn,new)
            conn.execute('UPDATE cases SET owner_user_id=?,updated_at=? WHERE id=?',(new,utcnow(),case_id))
            audit(conn,'case_owner_changed',actor,{'case_id':case_id,'old_owner_user_id':old,'new_owner_user_id':new})
            if action=='claim': audit(conn,'case_claimed',actor,{'case_id':case_id,'owner_user_id':new})
            return {'case_id':case_id,'owner_user_id':new}
        if action=='grant':
            typ=body.get('principal_type'); pid=body.get('principal_id'); access=body.get('access')
            if typ not in {'user','team'} or type(pid) is not int or pid<=0 or access not in {'viewer','editor'}:
                raise AccessError(400,'invalid principal or access')
            table='users' if typ=='user' else 'teams'
            if not conn.execute(f'SELECT id FROM {table} WHERE id=?',(pid,)).fetchone(): raise AccessError(404,'principal not found')
            col='user_id' if typ=='user' else 'team_id'
            if conn.execute(f'SELECT id FROM case_acl WHERE case_id=? AND {col}=?',(case_id,pid)).fetchone(): raise AccessError(409,'grant already exists; use PATCH')
            cur=conn.execute(f'INSERT INTO case_acl(case_id,{col},access) VALUES(?,?,?)',(case_id,pid,access)); acl_id=cur.lastrowid
            event='case_acl_granted'
        else:
            row=next((r for r in acl_rows(conn,case_id) if r['id']==acl_id),None)
            if row is None: raise AccessError(404,'grant not found')
            typ,pid,access=row['principal_type'],row['principal_id'],row['access']
            if action=='revoke':
                conn.execute('DELETE FROM case_acl WHERE id=?',(acl_id,)); event='case_acl_revoked'
            else:
                access=body.get('access')
                if access not in {'viewer','editor'}: raise AccessError(400,'invalid access')
                conn.execute('UPDATE case_acl SET access=? WHERE id=?',(access,acl_id)); event='case_acl_changed'
        audit(conn,event,actor,{'case_id':case_id,'principal_type':typ,'principal_id':pid,'access':access})
        return {'id':acl_id,'principal_type':typ,'principal_id':pid,'access':access}

def teams_api(store,user,method,tail,body,auth_enabled=True):
    with store.connect() as conn:
        conn.execute('BEGIN IMMEDIATE')
        u=identity(conn,user)
        if auth_enabled and (not u or not u['enabled'] or u['role']!='admin'): raise AccessError(403,'administrator required')
        actor=user['id'] or None
        if len(tail)>3 or (len(tail)>1 and tail[1]!='members') or (len(tail)==3 and method!='DELETE'): raise AccessError(404,'not found')
        tid=int(tail[0]) if tail else None
        team=conn.execute('SELECT * FROM teams WHERE id=?',(tid,)).fetchone() if tid else None
        if tid and not team: raise AccessError(404,'team not found')
        if method=='GET':
            if len(tail)>1 and tail[1]=='members': return [dict(r) for r in conn.execute('SELECT m.*,u.username,u.display_name,u.enabled FROM team_members m JOIN users u ON u.id=m.user_id WHERE team_id=? ORDER BY user_id',(tid,))]
            return dict(team) if team else [dict(r) for r in conn.execute('SELECT * FROM teams ORDER BY id')]
        if len(tail)>1 and tail[1]=='members':
            uid=int(tail[2]) if method=='DELETE' and len(tail)==3 else body.get('user_id')
            if type(uid) is not int or uid<=0: raise AccessError(400,'invalid user ID')
            if not conn.execute('SELECT id FROM users WHERE id=?',(uid,)).fetchone(): raise AccessError(404,'user not found')
            if method=='POST':
                if conn.execute('SELECT 1 FROM team_members WHERE team_id=? AND user_id=?',(tid,uid)).fetchone(): raise AccessError(409,'membership exists')
                conn.execute('INSERT INTO team_members VALUES(?,?,?)',(tid,uid,utcnow())); event='team_member_added'
            elif method=='DELETE':
                if not conn.execute('DELETE FROM team_members WHERE team_id=? AND user_id=?',(tid,uid)).rowcount: raise AccessError(404,'membership not found')
                event='team_member_removed'
            else: raise AccessError(400,'invalid team operation')
            audit(conn,event,actor,{'team_id':tid,'user_id':uid}); return {'team_id':tid,'user_id':uid}
        if method not in {'POST','PATCH'} or (method=='POST' and tid) or (method=='PATCH' and not tid): raise AccessError(400,'invalid team operation')
        name=body.get('name',team['name'] if team else '')
        description=body.get('description',team['description'] if team else '')
        enabled=body.get('enabled',bool(team['enabled']) if team else True)
        if not isinstance(name,str) or not name.strip() or len(name)>200 or not isinstance(description,str) or len(description)>4000 or type(enabled) is not bool: raise AccessError(400,'invalid team fields')
        if conn.execute('SELECT id FROM teams WHERE name=? AND id!=?',(name.strip(),tid or 0)).fetchone(): raise AccessError(409,'team name exists')
        now=utcnow()
        if tid: conn.execute('UPDATE teams SET name=?,description=?,enabled=?,updated_at=? WHERE id=?',(name.strip(),description,enabled,now,tid))
        else: tid=conn.execute('INSERT INTO teams(name,description,enabled,created_at,updated_at) VALUES(?,?,?,?,?)',(name.strip(),description,enabled,now,now)).lastrowid
        audit(conn,'team_updated' if team else 'team_created',actor,{'team_id':tid})
        if team and bool(team['enabled'])!=enabled: audit(conn,'team_enabled' if enabled else 'team_disabled',actor,{'team_id':tid})
        return dict(conn.execute('SELECT * FROM teams WHERE id=?',(tid,)).fetchone())
