from osint_tools.auth import hash_password, verify_password, token_hash, new_session, allowed, login_limited, note_login_failure
from osint_tools.storage import Store

def test_invalid_login_is_generic_and_audited(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_TOOLS_DATA_DIR",str(tmp_path/"data"))
    from osint_tools import server
    server.STORE=Store(tmp_path/"login.db"); monkeypatch.setattr(server,"AUTH_ENABLED",True)
    h=object.__new__(server.Handler); h.path="/api/v1/auth/login"; h._body=lambda limit: {"username":"missing","password":"secret"}
    captured={}; h._json=lambda status,payload: captured.update(status=status,payload=payload)
    h.do_POST()
    assert captured["status"]==401 and captured["payload"]["error"]["code"]=="invalid_credentials"
    assert server.STORE.list_audit()[0]["action"]=="login" and server.STORE.list_audit()[0]["outcome"]=="failure"

def test_password_hash_is_versioned_salted_and_constant_time_compatible():
    a,b=hash_password("correct horse"),hash_password("correct horse")
    assert a.startswith("scrypt$1$") and a!=b and verify_password("correct horse",a) and not verify_password("wrong",a)

def test_session_tokens_are_opaque_and_roles_are_centralized(tmp_path):
    s=Store(tmp_path/"db"); u=s.create_user("admin","Admin",hash_password("pw"),"admin"); token,csrf=new_session(); s.create_session(token_hash(token),u["id"],token_hash(csrf),"2999-01-01T00:00:00+00:00")
    assert token_hash(token)!=token and s.get_session(token_hash(token))["username"]=="admin" and allowed("analyst","viewer") and not allowed("viewer","analyst")

def test_audit_is_bounded_and_metadata_structured(tmp_path):
    s=Store(tmp_path/"db"); e=s.add_audit("login","failure",actor_username="x",metadata={"large":"z"*20000}); assert e["action"]=="login" and len(str(e["metadata"]))<=8200

def test_login_failure_limiter_is_bounded():
    key="m60-test"; [note_login_failure(key) for _ in range(10)]; assert login_limited(key)
