from __future__ import annotations
import uuid
from datetime import datetime, timezone
from .core import detect_target

NS=uuid.UUID('6f8f7b31-1e17-5cd8-9d9c-1e2dd7db7a17')
def _uuid(kind,key): return str(uuid.uuid5(NS,kind+':'+key))

def export_event(store,case_id):
    c=store.get_case(case_id)
    if c is None:return None
    attrs=[]
    for t in sorted(c['targets'],key=lambda x:x['id']):
        typ={'domain':'domain','ip':'ip-dst','url':'url'}.get(t['type'])
        if typ: attrs.append({'uuid':_uuid(typ,f'{case_id}:{t["normalized"]}'),'type':typ,'value':t['normalized'],'category':'Network activity','to_ids':False,'comment':'OSINT Tools observation'})
    for f in store.list_case_files(case_id):
        for alg,key in (('md5','md5'),('sha1','sha1'),('sha256','sha256')): attrs.append({'uuid':_uuid(alg,f'{case_id}:{f["sha256"]}:{alg}'),'type':alg,'value':f[key],'category':'Payload delivery','to_ids':False,'comment':'OSINT Tools file hash'})
    return {'Event':{'uuid':_uuid('event',str(case_id)),'info':str(c['name'])[:255],'date':str(c['created_at'])[:10],'timestamp':c['created_at'],'published':False,'threat_level_id':'1','analysis':0,'distribution':0,'Attribute':attrs,'Tag':[]}}

def import_event(store,doc, provenance=None, *, owner_user_id=None):
    e=doc.get('Event') if isinstance(doc,dict) else None
    if not isinstance(e,dict): raise ValueError('invalid MISP event')
    c=store.create_case(str(e.get('info') or 'Imported MISP event')[:200], owner_user_id=owner_user_id)
    counts={}; skipped=0
    for a in e.get('Attribute',[])[:1000]:
        typ,val=str(a.get('type','')),a.get('value')
        mapping={'domain':'domain','ip-src':'ip','ip-dst':'ip','url':'url','md5':'hash','sha1':'hash','sha256':'hash'}
        if typ not in mapping or not isinstance(val,str) or len(val)>2048: skipped+=1; continue
        try:
            d=detect_target(val) if mapping[typ] != 'hash' else detect_target(val)
            store.add_target(c['id'],d.type,d.value,d.normalized); counts[typ]=counts.get(typ,0)+1
        except Exception: skipped+=1
    return {'case_id':c['id'],'source_event_uuid':e.get('uuid'),'source_event_id':e.get('id'),'imported_counts':counts,'skipped_count':skipped,'provenance':provenance or {'source_format':'MISP'}}
