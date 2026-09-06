# Configuration

OSINT Tools uses environment variables for deployment configuration. Persistent application data belongs under `/data`; secrets belong in the deployment environment or secret-management mechanism, not in the repository or application-data exports.

## Core deployment

- `OSINT_TOOLS_AUTH_ENABLED` — authentication boundary; defaults to `true` in Compose.
- `OSINT_TOOLS_PORT_PUBLISHED` — Compose host port; defaults to `8090`.
- `OSINT_TOOLS_MAX_UPLOAD_BYTES` — maximum top-level upload size; default 25 MiB.

`OSINT_TOOLS_AUTH_ENABLED=false` is only for trusted, network-restricted deployments. It removes multi-user isolation.

## Provider credentials

All provider integrations are optional. OSINT Tools remains useful without API keys.

- `IPINFO_TOKEN`
- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`
- `SHODAN_API_KEY`
- `OSINT_TAXII_URL`, `OSINT_TAXII_TOKEN`, `OSINT_TAXII_ENABLED`
- `OSINT_MISP_URL`, `OSINT_MISP_API_KEY`, `OSINT_MISP_ENABLED`

Never put these values in source control, release notes, bug reports or screenshots/log excerpts shared publicly.

## Resource limits

The Compose definition exposes bounded archive, image, binary, signature/rule and similarity limits. Defaults are deliberately finite. Operators handling untrusted artifacts should increase them only after considering CPU, memory and disk impact.

Important groups include:

- `OSINT_TOOLS_ARCHIVE_*`
- `OSINT_TOOLS_IMAGE_MAX_PIXELS`
- `OSINT_TOOLS_BINARY_*`
- `OSINT_TOOLS_YARA_*`
- `OSINT_TOOLS_RULE*`
- `OSINT_TOOLS_HASHSET_*`
- `OSINT_TOOLS_SIMILAR_MAX_RESULTS`

## ClamAV

ClamAV is optional and disabled by default:

- `OSINT_TOOLS_CLAMAV_ENABLED`
- `OSINT_TOOLS_CLAMAV_HOST`
- `OSINT_TOOLS_CLAMAV_PORT`
- `OSINT_TOOLS_CLAMAV_TIMEOUT_SECONDS`
- `OSINT_TOOLS_CLAMAV_MAX_RESPONSE_BYTES`
- `OSINT_TOOLS_AV_SCAN_ON_UPLOAD`
- `OSINT_TOOLS_AV_MAX_ENGINES`

Keep clamd on a trusted local/container network. The application streams bytes to the configured engine; it does not require sharing application file paths with ClamAV.
