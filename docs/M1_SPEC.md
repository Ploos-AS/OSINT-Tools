# M1 — Core Passive OSINT

M1 turns the M0 foundation into a usable passive lookup service while preserving the OCI/Docker/Podman baseline.

## Included
- Unified target detection for domain, IP and HTTP(S) URL targets.
- DNS records: A, AAAA, CNAME, MX, NS, TXT, SOA and CAA.
- RDAP for domains and IP addresses through the public RDAP bootstrap service.
- IP classification and reverse-pointer generation.
- HTTP(S) HEAD inspection: final URL, status and response headers.
- TLS certificate inspection: protocol, cipher, SHA-256 fingerprint, subject, issuer, validity and SANs.
- Mail-domain view: MX, SPF and DMARC.
- JSON API under `/api/v1/`.

## Safety boundary
M1 is passive-first. HTTP/TLS inspectors resolve the destination before connecting and reject any address that Python classifies as non-global. This prevents the web API from becoming a convenient localhost/private-network SSRF primitive. Redirect handling remains subject to Python's HTTP stack; deployments exposed to untrusted users should additionally use network egress policy.

## API examples
- `/api/v1/target?value=example.com`
- `/api/v1/dns?domain=example.com`
- `/api/v1/rdap?value=example.com`
- `/api/v1/ip?value=1.1.1.1`
- `/api/v1/http?url=https%3A%2F%2Fexample.com`
- `/api/v1/tls?host=example.com`
- `/api/v1/mail?domain=example.com`

No provider API keys are required for M1.
