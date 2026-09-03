"""Bounded operator-configured TAXII/MISP clients and registries."""
from __future__ import annotations
import base64, json, socket
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import Request, urlopen

class SourceError(Exception):
    def __init__(self, code, message, status=400): self.code,self.message,self.status=code,message,status

class Source:
    def __init__(self,name,kind,url,enabled=False,token=None,username=None,password=None,api_key=None):
        self.name,self.kind,self.url,self.enabled=name,kind,url,enabled; self.token,self.username,self.password,self.api_key=token,username,password,api_key
        p=urlsplit(url) if url else None
        self.hostname=p.hostname if p else None
    def status(self): return {"name":self.name,"kind":self.kind,"enabled":self.enabled,"configured":bool(self.url and (self.kind=="taxii" or self.api_key or self.token or self.username)),"hostname":self.hostname}

class SourceRegistry:
    def __init__(self,sources): self.sources={s.name:s for s in sources}
    def list(self): return list(self.sources.values())
    def get(self,name): return self.sources.get(name)

def builtin_sources():
    enabled=lambda n: __import__('os').environ.get(n,'').lower() in {'1','true','yes','on'}
    import os
    return SourceRegistry([
      Source('taxii', 'taxii', os.environ.get('OSINT_TAXII_URL',''), enabled('OSINT_TAXII_ENABLED'), os.environ.get('OSINT_TAXII_TOKEN'), os.environ.get('OSINT_TAXII_USERNAME'), os.environ.get('OSINT_TAXII_PASSWORD')),
      Source('misp', 'misp', os.environ.get('OSINT_MISP_URL',''), enabled('OSINT_MISP_ENABLED'), api_key=os.environ.get('OSINT_MISP_API_KEY'))])

def _validate_url(url):
    p=urlsplit(url)
    if p.scheme not in {'https','http'} or p.username or p.password or p.fragment or not p.hostname: raise SourceError('invalid_source_url','configured source URL is invalid',400)
    return urlunsplit((p.scheme,p.netloc,p.path.rstrip('/'),'',''))

def fetch(source: Source, path: str, *, media: str, timeout=10, max_bytes=4*1024*1024):
    if not source.enabled: raise SourceError('source_disabled','source is disabled',409)
    if not source.url: raise SourceError('source_unconfigured','source is not configured',409)
    base=_validate_url(source.url); url=base+'/'+path.lstrip('/')
    headers={'Accept':media}
    if source.token: headers['Authorization']='Bearer '+source.token
    elif source.username: headers['Authorization']='Basic '+base64.b64encode((source.username+':'+(source.password or '')).encode()).decode()
    elif source.api_key: headers['Authorization']=source.api_key
    try:
        with urlopen(Request(url,headers=headers),timeout=timeout) as r:
            if r.status >= 400: raise SourceError('upstream_error','source returned an error',502)
            data=r.read(max_bytes+1)
            if len(data)>max_bytes: raise SourceError('response_too_large','source response exceeds limit',413)
            return json.loads(data)
    except SourceError: raise
    except TimeoutError: raise SourceError('timeout','source request timed out',504)
    except (OSError, socket.timeout): raise SourceError('connection_failed','source connection failed',502)
    except json.JSONDecodeError: raise SourceError('invalid_response','source returned invalid JSON',502)

def taxii_collections(source):
    doc=fetch(source,'taxii2/collections',media='application/taxii+json;version=2.1')
    out=[]
    for c in doc.get('collections',[])[:100]: out.append({k:c.get(k) for k in ('id','title','description','can_read','can_write','media_types')})
    return out

def taxii_objects(source, collection, limit=100):
    if not isinstance(collection,str) or len(collection)>200: raise SourceError('invalid_collection','collection identifier is invalid',400)
    return fetch(source,'taxii2/collections/'+quote(collection,safe='')+'/objects?limit='+str(max(1,min(int(limit),100))),media='application/taxii+json;version=2.1')

def misp_event(source,event):
    if not isinstance(event,str) or len(event)>128: raise SourceError('invalid_event','event identifier is invalid',400)
    return fetch(source,'events/view/'+quote(event,safe=''),media='application/json')
