#!/usr/bin/env python3
"""Black-box authenticated M6.0 HTTP qualification (qualification fixtures only)."""
import http.cookiejar, json, sys, urllib.error, urllib.request

BASE=sys.argv[1].rstrip("/"); PASSWORD="qualification-password-sentinel"
rows=[]
def row(name, ok, detail=""): rows.append((name,"PASS" if ok else "FAIL",detail if not ok else ""))
class Client:
 def __init__(self): self.jar=http.cookiejar.CookieJar(); self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar)); self.csrf=""
 def call(self, method, path, body=None, csrf=True, content_type="application/json"):
  data=None if body is None else (json.dumps(body).encode() if isinstance(body,(dict,list)) else body)
  h={"Content-Type":content_type};
  if csrf and self.csrf: h["X-CSRF-Token"]=self.csrf
  req=urllib.request.Request(BASE+path,data=data,headers=h,method=method)
  try:
   r=self.opener.open(req); raw=r.read(); return r.status,(json.loads(raw) if raw and "json" in r.headers.get("Content-Type","") else raw),dict(r.headers)
  except urllib.error.HTTPError as e:
   raw=e.read()
   try: raw=json.loads(raw)
   except Exception: pass
   return e.code,raw,dict(e.headers)
 def login(self,user,password=PASSWORD):
  s,b,h=self.call("POST","/api/v1/auth/login",{"username":user,"password":password},False); self.csrf=b.get("result",{}).get("csrf_token","") if isinstance(b,dict) else ""; return s,b,h
def main():
 if len(sys.argv)>2 and sys.argv[2]=="persistence":
  admin=Client(); sa,_,_=admin.login("admin"); analyst=Client(); sn,bn,_=analyst.login("analyst"); viewer=Client(); sv,_,_=viewer.login("viewer"); au=admin.call("GET","/api/v1/admin/audit?limit=200")[1]
  row("M6.0 auth persistence",sa==200 and sn==200 and bn.get("result",{}).get("role")=="analyst" and sv==401 and len(au.get("result",[]))>0)
  for n,s,d in rows: print(f"{n}|{s}|{d}")
  return 0 if all(s=="PASS" for _,s,_ in rows) else 1
 anon=Client(); s,i,_=anon.call("GET","/api/v1/info"); row("M6.0 runtime version",s==200 and i["version"]=="0.6.0")
 row("M6.0 auth enabled default",i.get("auth_enabled") is True); row("M6.0 bootstrap required",i.get("bootstrap_required") is True)
 s,b,_=anon.call("POST","/api/v1/auth/bootstrap",{"username":"admin","display_name":"Admin","password":PASSWORD},False); row("M6.0 bootstrap first admin",s==201)
 admin_id=b.get("result",{}).get("id"); s,_,_=anon.call("POST","/api/v1/auth/bootstrap",{"username":"other","password":PASSWORD},False); row("M6.0 bootstrap closed",s==409)
 admin=Client(); s,_,h=admin.login("admin"); row("M6.0 valid login",s==200); cookie=h.get("Set-Cookie",""); row("M6.0 session cookie flags",all(x in cookie for x in ("HttpOnly","SameSite=Lax","Path=/")))
 bad=Client(); s,b,_=bad.login("admin","wrong"); row("M6.0 invalid login",s==401 and b.get("error",{}).get("code")=="invalid_credentials")
 s,_,_=anon.call("GET","/api/v1/cases"); row("M6.0 anonymous 401",s==401)
 users={}
 for name,role,display in (("viewer","viewer","Viewer"),("analyst","analyst","Analyst"),("admin2","admin","Admin Two"),("hostile","viewer","<script>alert(9)</script>")):
  s,b,_=admin.call("POST","/api/v1/admin/users",{"username":name,"display_name":display,"password":PASSWORD,"role":role}); users[name]=b.get("result",{}).get("id"); row("M6.0 admin operation allowed" if name=="viewer" else "setup "+name,s==201)
 viewer=Client(); viewer.login("viewer"); analyst=Client(); analyst.login("analyst"); admin2=Client(); admin2.login("admin2")
 s,_,_=viewer.call("GET","/api/v1/cases"); row("M6.0 viewer read",s==200)
 s,_,_=viewer.call("POST","/api/v1/cases",{"name":"denied"}); row("M6.0 viewer mutation denied",s==403)
 s,b,_=analyst.call("POST","/api/v1/cases",{"name":"<script>alert(1)</script>","description":"<img src=x onerror=alert(2)>"}); case_id=b.get("result",{}).get("id"); row("M6.0 analyst mutation allowed",s==201)
 s,_,_=analyst.call("POST","/api/v1/admin/users",{"username":"nope","password":PASSWORD}); row("M6.0 analyst admin denied",s==403)
 s,_,_=analyst.call("PATCH",f"/api/v1/cases/{case_id}",{"status":"closed"}); row("M6.0 analytical CSRF valid",s==200)
 s,_,_=analyst.call("PATCH",f"/api/v1/cases/{case_id}",{"status":"open"},False); row("M6.0 analytical CSRF missing",s==403)
 old=analyst.csrf; analyst.csrf="wrong"; s,_,_=analyst.call("PATCH",f"/api/v1/cases/{case_id}",{"status":"open"}); row("M6.0 analytical CSRF wrong",s==403); analyst.csrf=viewer.csrf; s,_,_=analyst.call("PATCH",f"/api/v1/cases/{case_id}",{"status":"open"}); row("M6.0 CSRF cross-session rejection",s==403); analyst.csrf=old
 s,_,_=analyst.call("PATCH",f"/api/v1/cases/{case_id}?csrf_token={old}",{"status":"open"},False); row("M6.0 CSRF query-string-only rejection",s==403)
 s,b,_=analyst.call("POST",f"/api/v1/cases/{case_id}/targets",{"value":"1.1.1.1"}); target_id=b.get("result",{}).get("id")
 s,_,_=analyst.call("POST",f"/api/v1/targets/{target_id}/enrich",{}); row("M6.0 provider audit action",s==200)
 raw=b"qualification upload"; s,b,_=analyst.call("POST",f"/api/v1/cases/{case_id}/files",raw,True,"application/octet-stream"); file_id=b.get("result",{}).get("id"); row("M6.0 file upload action",s==201)
 s,_,_=viewer.call("POST",f"/api/v1/files/{file_id}/av/scan",{"engines":["clamav"]}); row("M6.0 viewer AV mutation denied",s==403)
 s,_,_=analyst.call("POST",f"/api/v1/files/{file_id}/av/scan",{"engines":["clamav"]}); row("M6.0 analyst AV scan",s==200)
 s,_,_=admin.call("POST",f"/api/v1/files/{file_id}/av/scan",{"engines":["clamav"]}); row("M6.0 admin AV scan",s==200)
 s,_,_=viewer.call("GET",f"/api/v1/files/{file_id}/av"); row("M6.0 viewer AV read",s==200)
 s,_,_=viewer.call("POST",f"/api/v1/targets/{target_id}/enrich",{}); row("M6.0 viewer provider mutation denied",s==403)
 s,_,_=admin.call("POST",f"/api/v1/targets/{target_id}/enrich",{}); row("M6.0 admin provider enrichment",s==200)
 s,bundle,_=analyst.call("GET",f"/api/v1/cases/{case_id}/bundle"); s,_,_=analyst.call("POST","/api/v1/cases/import",bundle,True,"application/zip"); row("M6.0 native import action",s==201)
 stix={"type":"bundle","id":"bundle--11111111-1111-4111-8111-111111111111","objects":[]}; s,_,_=analyst.call("POST","/api/v1/cases/import/stix",json.dumps(stix).encode(),True,"application/stix+json"); row("M6.0 STIX import action",s==201)
 misp={"Event":{"uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","info":"qualification","Attribute":[]}}; s,_,_=analyst.call("POST","/api/v1/cases/import/misp",misp); row("M6.0 MISP import action",s==201)
 s,_,_=viewer.call("POST","/api/v1/intelligence/sources/taxii/preview",{"collection":"fixture","limit":10}); row("M6.0 viewer TAXII preview",s==200)
 s,_,_=viewer.call("POST","/api/v1/intelligence/sources/taxii/import",{"collection":"fixture","limit":10}); row("M6.0 viewer TAXII import denied",s==403)
 s,_,_=analyst.call("POST","/api/v1/intelligence/sources/taxii/import",{"collection":"fixture","limit":10}); row("M6.0 analyst TAXII import",s==201)
 s,_,_=analyst.call("POST","/api/v1/intelligence/sources/misp/import",{"event":"fixture"}); row("M6.0 analyst MISP import",s==201)
 before=analyst.call("GET",f"/api/v1/cases/{case_id}")[1]; analyst.call("GET",f"/api/v1/cases/{case_id}/graph"); after=analyst.call("GET",f"/api/v1/cases/{case_id}")[1]; row("M6.0 GET non-mutation",before==after)
 s,html,h=analyst.call("GET",f"/cases/{case_id}"); text=html.decode("utf-8","replace") if isinstance(html,bytes) else str(html); csp=h.get("Content-Security-Policy",""); row("M6.0 authenticated XSS",s==200 and "<script>alert(1)</script>" not in text and "unsafe-inline" not in csp and "unsafe-eval" not in csp)
 s,_,_=admin.call("PATCH",f"/api/v1/admin/users/{users['viewer']}",{"enabled":False}); row("M6.0 administrative CSRF valid",s==200)
 s,_,_=admin.call("PATCH",f"/api/v1/admin/users/{users['hostile']}",{"role":"analyst"},False); saved=admin.csrf; admin.csrf="wrong"; sw,_,_=admin.call("PATCH",f"/api/v1/admin/users/{users['hostile']}",{"role":"analyst"}); admin.csrf=saved; row("M6.0 administrative CSRF missing/wrong",s==403 and sw==403)
 s,_,_=viewer.call("GET","/api/v1/cases"); row("M6.0 disabled-user session rejected",s==401)
 admin.call("PATCH",f"/api/v1/admin/users/{users['admin2']}",{"role":"analyst"}); s,_,_=admin.call("PATCH",f"/api/v1/admin/users/{admin_id}",{"role":"viewer"}); row("M6.0 final-admin protection",s==409)
 doomed=admin.call("POST","/api/v1/cases",{"name":"delete-me"})[1].get("result",{}).get("id"); s,_,_=admin.call("DELETE",f"/api/v1/cases/{doomed}",{}); row("M6.0 case deletion action",s==200)
 invalid=Client(); invalid.jar.set_cookie(http.cookiejar.Cookie(0,"osint_session","invalid",None,False,BASE.split("://",1)[1].split(":",1)[0],False,False,"/",True,False,None,False,None,None,{})); s,_,_=invalid.call("GET","/api/v1/cases"); row("M6.0 invalid session rejected",s==401)
 fresh=Client(); _,_,fh=fresh.login("analyst"); row("M6.0 fresh login session",fh.get("Set-Cookie","")!=h.get("Set-Cookie",""))
 s,_,_=fresh.call("POST","/api/v1/auth/logout",{}); s2,_,_=fresh.call("GET","/api/v1/cases"); row("M6.0 logout/session invalidation",s==200 and s2==401)
 limited=False
 for _ in range(11): limited=bad.login("limited-user","wrong")[0]==429 or limited
 row("M6.0 login rate limit",limited)
 # Admin audit is the persisted source of truth for all preceding operations.
 s,b,_=admin.call("GET","/api/v1/admin/audit?limit=200"); audits=b.get("result",[]) if isinstance(b,dict) else []; actions={x.get("action") for x in audits}
 row("M6.0 auth audit",{"login","logout"}<=actions and any(x.get("action")=="login" and x.get("outcome")=="failure" for x in audits))
 row("M6.0 admin audit",{"user_created","user_updated"}<=actions)
 row("M6.0 analytical audit",{"file_upload","provider_enrichment","case_import","stix_import","taxii_import","misp_import","case_delete"}<=actions)
 row("M6.0 file-upload audit","file_upload" in actions); row("M6.0 provider audit","provider_enrichment" in actions)
 row("M6.0 AV audit","av_scan" in actions); row("M6.0 native import audit","case_import" in actions); row("M6.0 STIX import audit","stix_import" in actions); row("M6.0 TAXII import audit","taxii_import" in actions); row("M6.0 MISP import audit","misp_import" in actions)
 serialized=json.dumps(audits); secrets=[PASSWORD,admin.csrf,analyst.csrf,"Authorization: Bearer qualification","qualification-provider-secret","qualification-taxii-sentinel","qualification-misp-sentinel"]
 row("M6.0 audit secret redaction",all(x not in serialized for x in secrets))
 for n,s,d in rows: print(f"{n}|{s}|{d}")
 return 0 if all(s=="PASS" for _,s,_ in rows) else 1
if __name__=="__main__": raise SystemExit(main())
