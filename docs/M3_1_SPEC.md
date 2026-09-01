# M3.1 Provider Framework and Qualification

## Architecture

Providers live under `osint_tools.providers`. A small explicit `ProviderRegistry` owns known adapters; `builtin_registry()` is the sole built-in discovery point. An adapter declares its stable ID, display metadata, supported target types and operations, required configuration names, and timeout. It returns `ProviderResult`, including parsed data, upstream HTTP status, rate-limit fields when supplied, and safe provider metadata. `provider_service.execute_provider` validates requests and persists results. HTTP routing remains in `server.py` and contains no provider-specific network logic.

This boundary leaves room for cache policy and provider quota accounting without creating a second case or artifact model. M3.1 implements exactly one adapter: IPinfo `lookup` for IP targets. Its endpoint host is fixed in server code (`https://ipinfo.io`); only a validated, existing target value becomes a path component. There is no arbitrary URL provider.

## Configuration and credentials

`IPINFO_TOKEN` configures IPinfo from the process environment. `OSINT_PROVIDER_IPINFO_ENABLED=false` explicitly disables the adapter. Provider APIs report configuration variable names and boolean state, never values. Credentials are not accepted in API bodies, stored in SQLite, added to artifacts, or incorporated into errors and logs. The bearer token is placed only in the outbound `Authorization` header. Upstream exceptions are converted to fixed safe messages.

Mounted-secret loading may be added later behind the same adapter configuration boundary. M3.1 guarantees environment-variable configuration.

## API

- `GET /api/v1/providers` lists safe status and capabilities.
- `GET /api/v1/providers/{provider}` returns one provider's safe status.
- `POST /api/v1/targets/{target_id}/providers/{provider}/{operation}` runs an operation and creates an M2 artifact.

Validation errors use structured 4xx responses (`target_not_found`, `unknown_provider`, `unknown_operation`, `unsupported_target_type`, `provider_disabled`, and `provider_not_configured`). Bounded upstream failures use structured 502/504 responses (`upstream_http_error`, `provider_unavailable`, `provider_timeout`, and `malformed_provider_response`). Unexpected HTTP handler failures return a fixed message, not an exception traceback.

## Provenance and persistence

A successful call creates a normal SQLite artifact under the existing target and case. Its type is `provider:{provider}:{operation}`, its source is the provider ID, and its data contains the provider result plus provider ID, operation, target ID/type/normalized value, UTC collection timestamp, upstream status, available rate-limit fields, and request-independent provider metadata. It contains no request headers or credentials. Existing SQLite persistence therefore carries provider artifacts across restarts.

## Security model

M2 SSRF validation remains unchanged. Provider clients may contact only their compiled-in public service host and expose no generic fetch primitive. API callers cannot supply or redirect the upstream base URL. Secret-redaction tests cover status, results, HTTP/URL failures, and API errors.

## Qualification

Run `scripts/qualify.sh` without prompts. Required Python, Git hygiene, SSRF, and secret-redaction failures return non-zero. When available, Docker qualification builds and runs Compose, checks health/info, exercises M2 case/target/DNS pivot behavior, exercises M3.1 status and clean unconfigured failures, restarts, and verifies persistence before cleanup. When available, Podman builds the same Containerfile and verifies health, APIs, and UID 10001. Missing runtimes are `SKIPPED`, never `PASS`.

The live IPinfo gate runs only when `IPINFO_TOKEN` is present and uses an eight-second timeout. Without credentials it is explicitly `SKIPPED`. Mocked provider tests qualify client parsing and failure semantics but do not constitute live-provider or container runtime qualification.
