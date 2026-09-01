from __future__ import annotations
import hashlib, ipaddress, json, re, socket, ssl, urllib.parse, urllib.request
from dataclasses import dataclass, asdict

UA = 'OSINT-Tools/0.1 (+passive-osint)'

@dataclass
class Target:
    type: str
    value: str
    normalized: str

def detect_target(value: str) -> Target:
    raw=value.strip()
    if not raw: raise ValueError('empty target')
    try:
        ip=ipaddress.ip_address(raw); return Target('ip', raw, ip.compressed)
    except ValueError: pass
    p=urllib.parse.urlparse(raw if '://' in raw else '//' + raw)
    if '://' in raw and p.hostname:
        return Target('url', raw, urllib.parse.urlunparse(p._replace(fragment='')))
    domain=raw.rstrip('.').lower()
    if re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', domain):
        return Target('domain', raw, domain)
    raise ValueError('unsupported target')

def ip_info(value: str):
    ip=ipaddress.ip_address(value)
    return {'ip':ip.compressed,'version':ip.version,'is_private':ip.is_private,'is_global':ip.is_global,
            'is_loopback':ip.is_loopback,'is_link_local':ip.is_link_local,'is_multicast':ip.is_multicast,
            'is_reserved':ip.is_reserved,'reverse_pointer':ip.reverse_pointer}

def dns_lookup(domain: str):
    import dns.resolver
    out={}
    for typ in ('A','AAAA','CNAME','MX','NS','TXT','SOA','CAA'):
        try:
            ans=dns.resolver.resolve(domain, typ, lifetime=5)
            out[typ]=[r.to_text() for r in ans]
        except Exception as e: out[typ]=[]
    return {'domain':domain,'records':out}

def rdap_lookup(value: str):
    try: ipaddress.ip_address(value); url='https://rdap.org/ip/'+urllib.parse.quote(value)
    except ValueError: url='https://rdap.org/domain/'+urllib.parse.quote(value)
    req=urllib.request.Request(url,headers={'User-Agent':UA,'Accept':'application/rdap+json, application/json'})
    with urllib.request.urlopen(req,timeout=10) as r: return json.load(r)

def _public_host(host: str):
    infos=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
    ips=sorted({x[4][0] for x in infos})
    if not ips: raise ValueError('host did not resolve')
    for s in ips:
        ip=ipaddress.ip_address(s)
        if not ip.is_global: raise ValueError('non-public destination blocked')
    return ips

def http_inspect(url: str):
    p=urllib.parse.urlparse(url)
    if p.scheme not in ('http','https') or not p.hostname: raise ValueError('http(s) URL required')
    ips=_public_host(p.hostname)
    req=urllib.request.Request(url,method='HEAD',headers={'User-Agent':UA})
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            return {'requested_url':url,'final_url':r.geturl(),'status':r.status,'resolved_ips':ips,'headers':dict(r.headers.items())}
    except urllib.error.HTTPError as e:
        return {'requested_url':url,'final_url':e.geturl(),'status':e.code,'resolved_ips':ips,'headers':dict(e.headers.items())}

def tls_inspect(host: str, port: int=443):
    _public_host(host)
    ctx=ssl.create_default_context()
    with socket.create_connection((host,port),timeout=10) as raw:
        with ctx.wrap_socket(raw,server_hostname=host) as s:
            cert=s.getpeercert(); der=s.getpeercert(binary_form=True)
            return {'host':host,'port':port,'protocol':s.version(),'cipher':s.cipher(),
                    'sha256':hashlib.sha256(der).hexdigest(), 'subject':cert.get('subject'),
                    'issuer':cert.get('issuer'),'notBefore':cert.get('notBefore'),'notAfter':cert.get('notAfter'),
                    'subjectAltName':cert.get('subjectAltName',())}

def mail_domain(domain: str):
    d=dns_lookup(domain)['records']
    spf=[x for x in d['TXT'] if 'v=spf1' in x.lower()]
    dmarc=dns_lookup('_dmarc.'+domain)['records']['TXT']
    return {'domain':domain,'mx':d['MX'],'spf':spf,'dmarc':dmarc}

def target_dict(value: str): return asdict(detect_target(value))
