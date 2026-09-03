from http.server import BaseHTTPRequestHandler, HTTPServer
import json, sys

STIX={"type":"bundle","id":"bundle--11111111-1111-4111-8111-111111111111","objects":[
 {"type":"grouping","spec_version":"2.1","id":"grouping--11111111-1111-4111-8111-111111111111","name":"Fixture <script>alert(1)</script>","description":"<img src=x onerror=alert(1)>","object_refs":[]},
 {"type":"domain-name","spec_version":"2.1","id":"domain-name--11111111-1111-4111-8111-111111111112","value":"fixture.example"},
 {"type":"ipv4-addr","spec_version":"2.1","id":"ipv4-addr--11111111-1111-4111-8111-111111111113","value":"192.0.2.10"},
 {"type":"url","spec_version":"2.1","id":"url--11111111-1111-4111-8111-111111111114","value":"https://fixture.example/x"},
 {"type":"relationship","spec_version":"2.1","id":"relationship--11111111-1111-4111-8111-111111111115","relationship_type":"related-to","source_ref":"domain-name--11111111-1111-4111-8111-111111111112","target_ref":"ipv4-addr--11111111-1111-4111-8111-111111111113"},
 {"type":"note","spec_version":"2.1","id":"note--11111111-1111-4111-8111-111111111116","content":"<script>alert(2)</script>","object_refs":[]},
 {"type":"malware","spec_version":"2.1","id":"malware--11111111-1111-4111-8111-111111111117","name":"unsupported"}]}
MISP={"Event":{"uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","info":"MISP <script>alert(1)</script>","Attribute":[{"type":"domain","value":"misp.example","comment":"<img src=x onerror=alert(1)>"},{"type":"ip-dst","value":"192.0.2.20"},{"type":"url","value":"https://misp.example/x"},{"type":"sha256","value":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},{"type":"unsupported","value":"x"}]}}
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  body = {"collections":[{"id":"fixture","title":"Fixture <script>alert(1)</script>","description":"<img src=x onerror=alert(1)>","can_read":True,"can_write":False,"media_types":["application/stix+json;version=2.1"]}]} if self.path.endswith('/collections') else STIX if '/objects' in self.path else MISP if '/events/view/' in self.path else {"title":"API Root"}
  data=json.dumps(body).encode(); self.send_response(200); self.send_header('Content-Type','application/taxii+json;version=2.1' if '/collections' in self.path or '/objects' in self.path else 'application/json'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
 def log_message(self,*a): pass
HTTPServer(('0.0.0.0',int(sys.argv[1])),H).serve_forever()
