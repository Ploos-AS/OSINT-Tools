# Installation

OSINT Tools is installed from the published OCI image. Release automation publishes the same tagged multi-architecture image to GHCR and Docker Hub. Before the first release tag exists these image names describe the release contract; they do not imply that `latest` is already published.

## Docker Compose

The repository Compose definition defaults to GHCR and keeps the source `build:` definition only so development and qualification can build the same container locally.

```sh
docker compose pull
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:${OSINT_TOOLS_PORT_PUBLISHED:-8090}/healthz
```

The default image is `ghcr.io/ploos-as/osint-tools:latest`. For a production release, pin an immutable version instead of `latest`:

```sh
OSINT_TOOLS_IMAGE=ghcr.io/ploos-as/osint-tools:1.0.0 docker compose up -d
```

Docker Hub is an equivalent publication target:

```sh
OSINT_TOOLS_IMAGE=ploosas/osint-tools:1.0.0 docker compose up -d
```

Persistent application state is stored in the named volume `osint-tools-data` mounted at `/data`. Authentication is enabled by default. Do not expose an authentication-disabled deployment to an untrusted network.

For source development only, `docker compose build` builds the checkout and tags it with the configured `OSINT_TOOLS_IMAGE`; ordinary production installation should pull a published immutable tag.

## Podman Quadlet

Install the supplied `.container` and `.volume` units in the appropriate user Quadlet directory. The supplied container unit defaults to `ghcr.io/ploos-as/osint-tools:latest`; pin `Image=` to the desired immutable release tag for production.

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

For Quadlet, substitute the configured published port. Confirm that the reported application version matches the immutable release you intended to install.

## Optional ClamAV

The Docker Compose `av` profile starts the separately maintained ClamAV service and database volume. The application image itself does not contain a ClamAV database.

```sh
OSINT_TOOLS_CLAMAV_ENABLED=true docker compose --profile av up -d
```

Do not publish clamd port 3310 to an untrusted network.
