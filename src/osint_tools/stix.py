"""Bounded conservative STIX 2.1 interoperability."""
from __future__ import annotations
import hashlib, json, re, uuid
from datetime import datetime, timezone

NS = uuid.UUID("2c93d6f4-6a5f-5b76-9f76-1d3c9b8e7a11")
SUPPORTED = {"bundle", "grouping", "domain-name", "ipv4-addr", "ipv6-addr", "url", "file", "relationship", "note"}

def sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NS, kind + ':' + key)}"

def _obj(kind, key, **fields):
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {"type": kind, "spec_version": "2.1", "id": sid(kind, key), "created": now, "modified": now, **fields}

def export_stix(store, case_id: int) -> dict | None:
    case = store.get_case(case_id)
    if case is None: return None
    objects=[]; refs=[]; target_ids={}
    for t in sorted(case["targets"], key=lambda x:x["id"]):
        typ={"domain":"domain-name","ip":"ipv4-addr" if "." in t["normalized"] else "ipv6-addr","url":"url"}.get(t["type"])
        if not typ: continue
        val=t["normalized"]; o=_obj(typ, f"{case_id}:{t['type']}:{val}"); o["value"] = val
        objects.append(o); target_ids[t["id"]]=o["id"]; refs.append(o["id"])
    for f in store.list_case_files(case_id):
        o=_obj("file", f"{case_id}:file:{f['sha256']}", hashes={"MD5":f["md5"],"SHA-1":f["sha1"],"SHA-256":f["sha256"]}, size=f["size"])
        objects.append(o); refs.append(o["id"])
    grouping=_obj("grouping", f"case:{case_id}", name=case["name"][:200], description=case.get("description","")[:4000], object_refs=refs)
    objects.insert(0, grouping)
    for r in sorted(case["relationships"], key=lambda x:x["id"]):
        if r["source_target_id"] in target_ids and r["destination_target_id"] in target_ids:
            o=_obj("relationship", f"{case_id}:rel:{r['id']}", relationship_type=r["relation"], source_ref=target_ids[r["source_target_id"]], target_ref=target_ids[r["destination_target_id"]])
            if r.get("artifact_id"): o["x_osint_tools_artifact_id"]=r["artifact_id"]
            objects.append(o)
    for n in sorted(case["notes"], key=lambda x:x["id"]):
        o=_obj("note", f"{case_id}:note:{n['id']}", content=str(n.get("body", ""))[:12000], object_refs=[target_ids[n["target_id"]]] if n.get("target_id") in target_ids else [])
        objects.append(o)
    return {"type":"bundle","id":f"bundle--{uuid.uuid4()}","objects":objects,"x_osint_tools_object_counts":{k:sum(x["type"]==k for x in objects) for k in sorted({x["type"] for x in objects})}}

def import_stix(store, raw: bytes, provenance: dict | None = None, *, owner_user_id=None) -> dict:
    if len(raw)>16*1024*1024: raise ValueError("STIX bundle exceeds maximum size")
    try: doc=json.loads(raw)
    except json.JSONDecodeError: raise ValueError("invalid STIX JSON") from None
    if not isinstance(doc,dict) or doc.get("type")!="bundle" or not isinstance(doc.get("objects"),list) or len(doc["objects"])>2000: raise ValueError("invalid STIX bundle")
    objs=doc["objects"]; byid={}
    for o in objs:
        if not isinstance(o,dict) or o.get("type") not in SUPPORTED or not re.match(r"^[a-z0-9-]+--[0-9a-fA-F-]{36}$",str(o.get("id",""))): continue
        if o["id"] in byid: raise ValueError("duplicate STIX object id")
        byid[o["id"]]=o
    grouping=next((o for o in objs if o.get("type")=="grouping"),None)
    name=(grouping or {}).get("name") or "Imported STIX case"
    case=store.create_case(str(name)[:200],str((grouping or {}).get("description", ""))[:4000], owner_user_id=owner_user_id)
    mapping={}; counts={}; skipped=[]
    for o in objs:
        typ=o.get("type");
        if typ not in {"domain-name","ipv4-addr","ipv6-addr","url"}: continue
        val=o.get("value")
        try:
            from .core import detect_target
            d=detect_target(str(val)); t=store.add_target(case["id"],d.type,d.value,d.normalized); mapping[o["id"]]=t["id"]; counts[typ]=counts.get(typ,0)+1
        except Exception: skipped.append(typ)
    for o in objs:
        if o.get("type")=="relationship" and o.get("source_ref") in mapping and o.get("target_ref") in mapping:
            store.add_relationship(case["id"],mapping[o["source_ref"]],str(o.get("relationship_type","related_to"))[:128],mapping[o["target_ref"]]); counts["relationship"]=counts.get("relationship",0)+1
        elif o.get("type")=="note":
            store.add_note(case["id"],str(o.get("content",""))[:12000]); counts["note"]=counts.get("note",0)+1
    unsupported=sorted({o.get("type") for o in objs if o.get("type") not in SUPPORTED})
    return {"case_id":case["id"],"source_bundle_id":doc.get("id"),"imported_counts":counts,"unsupported_types":unsupported,"skipped_count":len(skipped),"provenance":provenance or {"source_format":"STIX"}}
