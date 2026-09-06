# Troubleshooting

## Service does not become healthy

Check container/service status and logs first:

```sh
docker compose ps
docker compose logs --tail=200 osint-tools
```

or for rootless Quadlet:

```sh
systemctl --user status osint-tools.service
journalctl --user -u osint-tools.service -n 200 --no-pager
```

Verify the configured published port and that `/data` is writable by the non-root container process.

## Authentication problems

Confirm that `OSINT_TOOLS_AUTH_ENABLED` has the intended value. Authentication-disabled mode is intentionally different from multi-user mode and should not be exposed to an untrusted network.

Do not copy session cookies, CSRF tokens, passwords or provider credentials into public issue reports.

## Provider failures

Provider failures do not necessarily mean the application is unhealthy. Check whether the provider is enabled, whether credentials/endpoints are configured, and whether the provider reports a rate-limit or structured remote error. Core no-key functionality should remain available.

## Upload/parser failures

Check the configured upload and parser limits before raising them. Large archives, compression bombs, oversized images and high-cardinality binaries are intentionally bounded.

## ClamAV unavailable

Confirm that ClamAV is explicitly enabled, that clamd is reachable on the configured host/port, and—when using Compose—that the `av` profile is running. Do not expose clamd directly to untrusted networks.

## Upgrade failure

Do not attempt to solve a failed schema upgrade by starting an older image against newly migrated data. Stop the deployment and restore the pre-upgrade backup before returning to the previous release.

## What to include in a bug report

Include the OSINT Tools version, exact OCI image tag/digest if known, deployment method, architecture, relevant sanitized logs and reproduction steps. Remove passwords, cookies, CSRF/session values, provider tokens/API keys, private evidence and other sensitive case data.
