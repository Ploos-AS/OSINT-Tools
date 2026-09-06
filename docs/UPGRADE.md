# Upgrade

The supported release upgrade sequence is **stop → backup → pull the new immutable release → start → verify**.

## Docker Compose

1. Record the current application version and image/tag.
2. Stop the application so the `/data` state is quiescent.
3. Back up the complete application-data volume as described in `BACKUP_RESTORE.md`.
4. Change/pin the deployment to the new release tag.
5. Pull and start the new image.
6. Verify `/healthz`, `/api/v1/info`, representative cases/files and authentication/ACL behavior.

Typical lifecycle commands are:

```sh
docker compose stop osint-tools
# perform backup
docker compose pull osint-tools
docker compose up -d osint-tools
curl -fsS http://127.0.0.1:${OSINT_TOOLS_PORT_PUBLISHED:-8090}/healthz
curl -fsS http://127.0.0.1:${OSINT_TOOLS_PORT_PUBLISHED:-8090}/api/v1/info
```

## Podman Quadlet

Stop the unit, back up the volume, update the image tag in the Quadlet, reload systemd and restart:

```sh
systemctl --user stop osint-tools.service
# perform backup
systemctl --user daemon-reload
systemctl --user start osint-tools.service
systemctl --user status osint-tools.service
```

## Schema migrations and rollback

Schema migrations are forward upgrades. A downgrade across a schema migration is not promised. Do not start an older application version against a data directory that has already been migrated by a newer version.

Rollback means: stop the failed/new version, restore the pre-upgrade backup compatible with the old version, restore the old immutable image/tag, start and verify.

Release notes must call out persistent-schema changes explicitly.
