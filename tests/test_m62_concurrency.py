"""M6.2 deterministic authorization/concurrency qualification.

Security mutations commit before a protected mutation is released. The protected
mutation must re-read current authorization state at its transaction boundary.
"""
from __future__ import annotations
import threading
import pytest
from osint_tools.case_access import AccessError, case_admin, require_case_access, teams_api
from osint_tools.storage import Store, utcnow

@pytest.fixture
def model(tmp_path):
    store=Store(tmp_path/'db')
    admin=store.create_user('admin','Admin','fixture','admin')
    owner=store.create_user('owner','Owner','fixture','analyst')
    analyst=store.create_user('analyst','Analyst','fixture','analyst')
    case=store.create_case('private',owner_user_id=owner['id'])
    return store,admin,owner,analyst,case

def protected_after_barrier(store,case_id,user,barrier,results):
    barrier.wait(timeout=5)
    try:
        with store.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            require_case_access(conn,case_id,user,'editor')
            conn.execute('INSERT INTO notes(case_id,body,created_at,updated_at) VALUES(?,?,?,?)',(case_id,'must-not-land',utcnow(),utcnow()))
        results.append('written')
    except AccessError as exc:
        results.append(exc.status)

def run_revocation_race(store,mutate,case_id,user):
    barrier=threading.Barrier(2); results=[]
    worker=threading.Thread(target=protected_after_barrier,args=(store,case_id,user,barrier,results),daemon=True)
    worker.start(); mutate(); barrier.wait(timeout=5); worker.join(timeout=5)
    assert not worker.is_alive()
    assert results==[404]
    assert store.get_case(case_id)['notes']==[]

def test_owner_transfer_wins_before_stale_owner_mutation(model):
    s,_a,owner,analyst,c=model
    run_revocation_race(s,lambda: case_admin(s,owner,c['id'],'owner',{'owner_user_id':analyst['id']}),c['id'],owner)

def test_direct_acl_revocation_wins_before_mutation(model):
    s,_a,owner,analyst,c=model
    grant=case_admin(s,owner,c['id'],'grant',{'principal_type':'user','principal_id':analyst['id'],'access':'editor'})
    run_revocation_race(s,lambda: case_admin(s,owner,c['id'],'revoke',{},acl_id=grant['id']),c['id'],analyst)

def test_team_membership_removal_wins_before_mutation(model):
    s,admin,owner,analyst,c=model
    team=teams_api(s,admin,'POST',[],{'name':'responders'})
    teams_api(s,admin,'POST',[str(team['id']),'members'],{'user_id':analyst['id']})
    case_admin(s,owner,c['id'],'grant',{'principal_type':'team','principal_id':team['id'],'access':'editor'})
    run_revocation_race(s,lambda: teams_api(s,admin,'DELETE',[str(team['id']),'members',str(analyst['id'])],{}),c['id'],analyst)

def test_disabled_user_cannot_mutate_with_stale_session_identity(model):
    s,_a,owner,analyst,c=model
    case_admin(s,owner,c['id'],'grant',{'principal_type':'user','principal_id':analyst['id'],'access':'editor'})
    run_revocation_race(s,lambda: s.update_user(analyst['id'],enabled=False),c['id'],analyst)
