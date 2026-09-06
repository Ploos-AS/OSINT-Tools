# Installation

OSINT Tools is intended to be installed from a published OCI image. Until the first published release exists, the repository's development Compose/Quadlet definitions remain build-oriented; do not mistake `osint-tools:dev` for a released image.

## Docker Compose

For a released version, use the repository Compose definition with its image reference pinned to the desired release tag. Persistent application state must be mounted at `/data`.

```sh
docker compose pull
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:${OSINT_TOOLS_PORT_PUBLISHED:-8090}/healthz
```

The current development Compose publishes host port 8090 by default and stores `/data` in the named volume `osint-tools-data`.

Authentication is enabled by default. Do not expose an authentication-disabled deployment to an untrusted network.

## Podman Quadlet

Install the supplied `.container` and `.volume` units in the appropriate user Quadlet directory, adjust the image to the desired published release, then reload and start the unit:

```sh
systemctl --user daemon-reload
systemctl --user enable --now osint-tools.service
systemctl --user status osint-tools.service
curl -fsS http://127.0.0.1:8080/healthz
```

The application container runs without root privileges and persists application state at `/data`.

## Verification

After installation verify at minimum:

```sh
curl -fsS http://127.0.0.1:8090/healthz
curl -fsS http://127.0.0.1:8090/api/v1/info
```

For Quadlet, substitute the configured published port. Confirm that the reported application version matches the release you intended to install.

## Optional ClamAV

The Docker Compose `av` profile starts the separately maintained ClamAV service and database volume. The application image itself does not contain a ClamAV database.

```sh
OSINT_TOOLS_CLAMAV_ENABLED=true docker compose --profile av up -d
```

Do not publish clamd port 3310 to an untrusted network.
