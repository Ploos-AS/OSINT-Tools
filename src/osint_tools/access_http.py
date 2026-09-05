"""One request boundary for all case-owned routes, including UI aliases."""
from functools import wraps
from .case_access import AccessError, require_case_access, case_admin, teams_api, acl_rows

def scoped(method):
    @wraps(method)
    def wrapped(self):
        from . import server
        store=server.STORE; enabled=server.AUTH_ENABLED
        try:
            _,parts=self._parts()
            verb=method.__name__[3:]
            route=parts[2:] if parts[:2]==['api','v1'] else parts[1:] if parts[:1]==['ui'] else parts
            case_id=None
            if len(route)>1 and route[0] in {'cases','targets','files'} and route[1]!='import':
                oid=int(route[1])
                if route[0]=='cases': case_id=oid
                else:
                    with store.connect() as conn:
                        row=conn.execute(f'SELECT case_id FROM {route[0]} WHERE id=?',(oid,)).fetchone()
                    case_id=row['case_id'] if row else -1
            self._case_scope=case_id
            management=(parts[:2]==['api','v1'] and route[:2]==['admin','teams']) or (case_id is not None and route[0]=='cases' and len(route)>2 and route[2] in {'acl','access','owner','claim'})
            if not enabled and not management: return method(self)
            if case_id is not None or management:
                user=self._require_auth()
                if user is None: return
                if verb!='GET' and not self._csrf_ok(user): raise AccessError(403,'CSRF token required')
                if case_id is not None:
                    required='viewer' if verb=='GET' else 'owner' if management or (route[0]=='cases' and len(route)==2) else 'editor'
                    with store.connect() as conn: require_case_access(conn,case_id,user,required,enabled)
                if management:
                    if route[0]=='cases':
                        valid=(verb=='GET' and len(route)==3 and route[2] in {'access','acl'}) or (verb=='POST' and len(route)==3 and route[2] in {'acl','claim'}) or (verb=='PATCH' and len(route)==3 and route[2]=='owner') or (verb in {'PATCH','DELETE'} and len(route)==4 and route[2]=='acl')
                        if not valid: raise AccessError(404,'not found')
                    body=self._body(64*1024) if verb in {'POST','PATCH'} else {}
                    if not isinstance(body,dict): raise AccessError(400,'object required')
                    if route[:2]==['admin','teams']:
                        result=teams_api(store,user,verb,route[2:],body,enabled)
                    elif verb=='GET':
                        with store.connect() as conn:
                            access=require_case_access(conn,case_id,user,'owner' if route[2]=='acl' else 'viewer',enabled)
                            owner=conn.execute('SELECT owner_user_id FROM cases WHERE id=?',(case_id,)).fetchone()[0]
                            result=acl_rows(conn,case_id) if route[2]=='acl' else {'case_id':case_id,'owner_user_id':owner,'effective_access':access,'admin_override':enabled and user['role']=='admin'}
                    else:
                        action={('POST','acl'):'grant',('PATCH','acl'):'change',('DELETE','acl'):'revoke',('PATCH','owner'):'owner',('POST','claim'):'claim'}.get((verb,route[2]))
                        if not action: raise AccessError(400,'invalid access operation')
                        result=case_admin(store,user,case_id,action,body,int(route[3]) if len(route)>3 else None,enabled)
                    return self._json(201 if verb=='POST' else 200,{'ok':True,'result':result})
            return method(self)
        except AccessError as exc:
            return self._json(exc.status,{'ok':False,'error':{'code':'not_found' if exc.status==404 else 'forbidden' if exc.status==403 else 'invalid_request','message':exc.message}})
        except (ValueError,TypeError,OverflowError):
            return self._json(400,{'ok':False,'error':'invalid request'})
    return wrapped
