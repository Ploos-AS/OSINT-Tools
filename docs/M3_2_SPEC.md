# M3.2 Provider Expansion and Enrichment Pivots

## Curated providers

M3.2 retains IPinfo and adds three complementary adapters through the M3.1 registry:

- **VirusTotal** provides reputation reports for IP, domain, URL, and hash targets via `lookup`. It requires `VIRUSTOTAL_API_KEY`.
- **AbuseIPDB** provides IP abuse confidence and report metadata via `check`. It requires `ABUSEIPDB_API_KEY`.
- **Shodan** provides passive IP host, service, and hostname context via `host`. It requires `SHODAN_API_KEY`.

These services have documented fixed HTTPS APIs, straightforward API-key authentication, and useful key tiers. They require no scraping, browser automation, OAuth, or client-side secrets. Each can be disabled using `OSINT_PROVIDER_<PROVIDER>_ENABLED=false`. IPinfo continues to use `IPINFO_TOKEN` and `lookup` for IP targets.

## Targets and orchestration

Hash targets are detected only when the entire input is 32, 40, or 64 hexadecimal characters and are normalized to lowercase. Arbitrary-length hexadecimal strings are not hashes.

Direct execution remains `POST /api/v1/targets/{id}/providers/{provider}/{operation}` with explicit M3.1 errors. `POST /api/v1/targets/{id}/enrich` selects applicable providers, skips disabled or unconfigured providers, runs each configured provider's declared default operation independently, and returns per-provider `success`, `skipped`, or `failed` results plus a summary. One failure does not roll back another provider's successful artifact.

## Pivots and provenance

Providers emit explicit pivot candidates; orchestration never searches arbitrary response strings. IPinfo and Shodan may promote validated hostname values to normalized domain targets with `observed_hostname` relationships. Invalid values and self-pivots are ignored.

Schema version 2 adds nullable `relationships.artifact_id`, referencing the provider artifact that caused a pivot. Existing schema-version-1 databases are upgraded with an additive `ALTER TABLE`; existing data is preserved. Provider artifacts retain provider, operation, source target, UTC collection time, upstream status, rate limits, and safe provider metadata.

## Rate limits and failures

Available headers are normalized as `limit`, `remaining`, and `reset` without invented values. HTTP 429 becomes `rate_limit_exhausted`, preserving safe upstream status and available rate-limit fields. During generic enrichment this is a provider-level failure and other providers continue. Timeouts, malformed responses, other HTTP failures, and transport failures retain structured redacted errors.

## Security boundaries

All provider hosts and HTTPS schemes are fixed in provider code, and provider HTTP clients do not follow redirects. Existing targets supply only validated normalized identifiers; there is no client-controlled base URL or arbitrary fetch endpoint. VirusTotal and AbuseIPDB keys are headers. IPinfo uses a bearer header. Shodan's documented API uses its key as an upstream query parameter; fixed error conversion prevents that URL from reaching API errors or application logs.

M2 redirect validation and private/link-local blocking remain unchanged. DNS validation-versus-connect rebinding remains a residual risk for the existing generic HTTP inspection primitive; M3.2 does not claim to eliminate that TOCTOU class.

## Qualification

`scripts/qualify.sh` retains M3.1 gates and adds registry, generic enrichment, all-skipped, persistence, pivot provenance, rate-limit, malformed-response, upstream-failure, and per-provider secret tests. Docker and Podman runtime gates exercise provider status and enrichment while unconfigured. Live calls are separate per provider, bounded by timeouts, run only when their credential exists, and never print responses or credentials. Mocked tests are not live qualification. Podman may warn that OCI image format does not preserve Docker `HEALTHCHECK`; runtime qualification probes health directly and verifies UID 10001.
