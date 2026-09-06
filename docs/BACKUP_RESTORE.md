# Backup and Restore

The authoritative backup boundary is the complete persistent application `/data` state. It contains the SQLite database and content-addressed uploaded-file storage. Take backups while the application is stopped/quiescent unless a future release explicitly documents an online-backup mechanism.

Provider credentials and other deployment secrets are not part of `/data` and must be backed up separately using the operator's secret-management process.

## Docker named volume

Stop the application first:

```sh
docker compose stop osint-tools
mkdir -p backup
docker run --rm \
  -v osint-tools_osint-tools-data:/data:ro \
  -v "$PWD/backup:/backup" \
  alpine:3.22 \
  tar -C /data -czf /backup/osint-tools-data.tgz .
```

Compose normally prefixes named volumes with the project name. Confirm the actual volume first with `docker volume ls`; do not assume the example prefix if the project name differs.

Restore only into a stopped deployment. Prefer a new/empty target volume and retain the original backup until verification succeeds:

```sh
docker run --rm \
  -v osint-tools_osint-tools-data:/data \
  -v "$PWD/backup:/backup:ro" \
  alpine:3.22 \
  sh -c 'rm -rf /data/* /data/.[!.]* /data/..?* 2>/dev/null || true; tar -C /data -xzf /backup/osint-tools-data.tgz'
```

Then start OSINT Tools and verify health, version, representative cases, files and authorization state.

## Podman/Quadlet volume

Stop the user service first. Determine the actual volume mount point rather than assuming a storage path:

```sh
systemctl --user stop osint-tools.service
podman volume inspect osint-tools-data
```

A portable approach is to mount the named volume into a short-lived helper container and archive `/data`, analogous to the Docker example:

```sh
mkdir -p backup
podman run --rm \
  -v osint-tools-data:/data:ro,Z \
  -v "$PWD/backup:/backup:Z" \
  docker.io/library/alpine:3.22 \
  tar -C /data -czf /backup/osint-tools-data.tgz .
```

Restore into the stopped volume with a helper container, then restart the Quadlet and verify the same application and authorization invariants.

## Backup verification

A backup is not considered proven merely because the archive command succeeded. M7.2 adds mechanical backup/restore qualification that must verify database state, uploaded bytes, ACL/team/auth state and successful application restart.
