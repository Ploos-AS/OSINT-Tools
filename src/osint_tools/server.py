import json, os, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from . import __version__
from .core import target_dict, ip_info, dns_lookup, rdap_lookup, http_inspect, tls_inspect, mail_domain
HOST=os.environ.get('OSINT_TOOLS_HOST','0.0.0.0'); PORT=int(os.environ.get('OSINT_TOOLS_PORT','8080')); DATA_DIR=os.environ.get('OSINT_TOOLS_DATA_DIR','/data')
class Handler(BaseHTTPRequestHandler):
    def _json(self,status,payload):
        body=json.dumps(payload,default=str).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        p=urllib.parse.urlparse(self.path); q=urllib.parse.parse_qs(p.query)
        try:
            if p.path=='/healthz': return self._json(200,{'status':'ok'})
            if p.path=='/api/v1/info': return self._json(200,{'name':'OSINT Tools','version':__version__,'milestone':'M1','passive_first':True,'data_dir':DATA_DIR})
            value=lambda n: q[n][0]
            routes={'/api/v1/target':lambda:target_dict(value('value')),
                    '/api/v1/ip':lambda:ip_info(value('value')),
                    '/api/v1/dns':lambda:dns_lookup(value('domain')),
                    '/api/v1/rdap':lambda:rdap_lookup(value('value')),
                    '/api/v1/http':lambda:http_inspect(value('url')),
                    '/api/v1/tls':lambda:tls_inspect(value('host'),int(q.get('port',['443'])[0])),
                    '/api/v1/mail':lambda:mail_domain(value('domain'))}
            if p.path in routes: return self._json(200,{'ok':True,'result':routes[p.path]()})
            self._json(404,{'error':'not_found'})
        except (ValueError,KeyError) as e: self._json(400,{'error':'bad_request','detail':str(e)})
        except Exception as e: self._json(502,{'error':'lookup_failed','detail':str(e)})
    def log_message(self,fmt,*args): print('%s - %s'%(self.address_string(),fmt%args),flush=True)
def main():
    os.makedirs(DATA_DIR,exist_ok=True); s=ThreadingHTTPServer((HOST,PORT),Handler); print(f'OSINT Tools M1 listening on {HOST}:{PORT}',flush=True); s.serve_forever()
if __name__=='__main__': main()
