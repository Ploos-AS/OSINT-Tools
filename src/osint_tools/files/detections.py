from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from dataclasses import replace

from .hashsets import HashSetError, validate_hashset
from .similarity import ALGORITHM, IMPLEMENTATION_VERSION, distance, fingerprint
from .yara_engine import ENGINE, ENGINE_VERSION, RuleError, YaraLimits, compile_rules, match_rules

BUILTIN_RULES = '''rule OSINT_Tools_Harmless_Demo : demonstration harmless {
 meta:
  title = "OSINT Tools harmless deterministic demonstration"
  purpose = "qualification"
 strings:
  $demo = "OSINT_TOOLS_DEMO_SIGNATURE" ascii
 condition:
  any of them
}'''


@dataclass(frozen=True)
class DetectionLimits:
    yara: YaraLimits = YaraLimits()
    hashset_max_entries: int = 100000
    hashset_max_bytes: int = 4 * 1024 * 1024
    similar_max_results: int = 100
    max_scan_bytes: int = 25 * 1024 * 1024
    max_rule_packs: int = 100


def ensure_builtin_rules(store) -> dict:
    pack={"name":"osint-tools-demo","version":"1","namespace":"osint_tools_builtin","source":"OSINT Tools","description":"Harmless deterministic demonstration rules; project MIT license","rules_text":BUILTIN_RULES,"rules_sha256":hashlib.sha256(BUILTIN_RULES.encode()).hexdigest()}
    return store.add_rule_pack(pack)


def import_rule_pack(store, payload: dict, limits: DetectionLimits) -> dict:
    name=str(payload.get("name","")).strip()[:128]; version=str(payload.get("version","")).strip()[:64]
    namespace=str(payload.get("namespace","")).strip()[:128]; rules=str(payload.get("rules", ""))
    if not name or not version or not namespace: raise RuleError("name, version, and namespace are required")
    compile_rules(rules,limits.yara)
    digest=hashlib.sha256(rules.encode()).hexdigest()
    for existing in store.list_rule_packs(True):
        if existing["name"]==name and existing["version"]==version and existing["rules_sha256"]!=digest:
            raise RuleError("rule-pack name and version already identify different content")
    return store.add_rule_pack({"name":name,"version":version,"namespace":namespace,"source":str(payload.get("source","local"))[:256],"description":str(payload.get("description",""))[:1024],"rules_text":rules,"rules_sha256":digest})


def import_hashset(store, payload: dict, limits: DetectionLimits) -> dict:
    encoded=json.dumps(payload,separators=(",",":"))
    if len(encoded.encode())>limits.hashset_max_bytes: raise HashSetError("hash-set import exceeds maximum size")
    validated=validate_hashset(payload,limits.hashset_max_entries)
    validated["content_sha256"]=hashlib.sha256(json.dumps(validated,separators=(",",":"),sort_keys=True).encode()).hexdigest()
    try: return store.import_hash_set(validated)
    except ValueError as exc: raise HashSetError(str(exc)) from None


def analyze_detections(store, objects, file_record: dict, limits: DetectionLimits) -> dict:
    ensure_builtin_rules(store)
    path=objects.physical_path(file_record["storage_id"])
    with path.open("rb") as stream: data=stream.read(limits.max_scan_bytes+1)
    scan_limited=len(data)>limits.max_scan_bytes; data=data[:limits.max_scan_bytes]
    records=[]; statuses=[]
    packs=store.list_rule_packs(True)[:limits.max_rule_packs]
    yara_deadline=time.monotonic()+max(0.0,limits.yara.timeout_seconds)
    yara_match_count=0
    for pack in packs:
        remaining_matches=limits.yara.max_matches-yara_match_count
        remaining_time=yara_deadline-time.monotonic()
        if remaining_matches<=0:
            statuses.append({"rule_pack_id":pack["id"],"name":pack["name"],"version":pack["version"],"status":"match_limit","truncated":True}); continue
        if remaining_time<=0:
            statuses.append({"rule_pack_id":pack["id"],"name":pack["name"],"version":pack["version"],"status":"timeout","truncated":True}); continue
        try:
            compiled=compile_rules(pack["rules_text"],limits.yara)
            status,matches,truncated=match_rules(data,compiled,replace(limits.yara,timeout_seconds=remaining_time,max_matches=remaining_matches))
        except RuleError:
            status,matches,truncated="invalid_rules",[],False
        statuses.append({"rule_pack_id":pack["id"],"name":pack["name"],"version":pack["version"],"status":status,"truncated":truncated})
        for match in matches:
            records.append({"analyzer":ENGINE,"analyzer_version":ENGINE_VERSION,"method":"yara","signature_id":match["rule_identifier"],"namespace":pack["namespace"],"title":str(match["metadata"].get("title",match["rule_identifier"]))[:256],"tags":match["tags"],"metadata":{"rule_metadata":match["metadata"],"string_matches":match["string_matches"]},"result":"match","provenance":{"rule_pack_id":pack["id"],"rule_pack_name":pack["name"],"rule_pack_version":pack["version"],"rules_sha256":pack["rules_sha256"],"source":pack["source"]}})
        yara_match_count+=len(matches)
    hashes={"md5":file_record["md5"],"sha1":file_record["sha1"],"sha256":file_record["sha256"]}
    for entry in store.matching_hash_entries(hashes):
        records.append({"analyzer":"osint-tools-known-hash","analyzer_version":"1","method":"known_hash","signature_id":f'{entry["algorithm"]}:{entry["digest"]}',"namespace":entry["set_name"],"title":entry["label"] or entry["set_name"],"tags":entry["tags"],"metadata":{"algorithm":entry["algorithm"],"digest":entry["digest"],"entry_metadata":entry["metadata"],"category":entry["set_category"]},"result":"match","provenance":{"hash_set_id":entry["hash_set_id"],"hash_set_name":entry["set_name"],"hash_set_version":entry["set_version"],"source":entry["set_source"]}})
    current=store.get_fingerprint(file_record["sha256"],ALGORITHM)
    if current is None or current["implementation_version"]!=IMPLEMENTATION_VERSION:
        store.put_fingerprint(file_record["sha256"],ALGORITHM,IMPLEMENTATION_VERSION,fingerprint(data))
    summary={"status":"success","scan_limited":scan_limited,"yara":statuses,"detection_count":len(records),"fingerprint":{"algorithm":ALGORITHM,"implementation_version":IMPLEMENTATION_VERSION}}
    return store.replace_local_detections(file_record["id"],summary,records)


def similar_files(store, file_id: int, limit: int, max_results: int) -> list[dict]:
    file=store.get_file(file_id)
    if file is None: raise KeyError("file not found")
    own=store.get_fingerprint(file["sha256"],ALGORITHM)
    if own is None: return []
    maximum=max(1,min(limit,max_results)); results=[]
    for item in store.similarity_candidates(file_id,ALGORITHM):
        item["algorithm"]=ALGORITHM; item["distance"]=distance(own["fingerprint"],item.pop("fingerprint")); item["exact_duplicate"]=item["object_sha256"]==file["sha256"]
        results.append(item)
    return sorted(results,key=lambda item:(item["distance"],item["file_id"]))[:maximum]
