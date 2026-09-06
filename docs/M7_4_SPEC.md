# M7.4 Distribution and Documentation Polish

## Goal

Make operator-facing deployment definitions match the M7 release contract without weakening the existing source-build qualification path.

## Contract

- `compose.yaml` defaults to `ghcr.io/ploos-as/osint-tools:latest` through `OSINT_TOOLS_IMAGE`, while retaining `build:` for development and qualification.
- Operators are instructed to pin immutable full-version tags for production.
- Docker Hub `ploosas/osint-tools` is documented as an equivalent release publication target.
- Quadlet defaults to the GHCR release image rather than a localhost development tag.
- The distribution model is documented as Forgejo canonical, GitHub + Codeberg source mirrors, GHCR + Docker Hub OCI publication, and optional Harbor later.
- Documentation must distinguish planned/not-yet-published release references from already verified releases.
- No M7.4 change creates a Git tag or publishes an OCI image.

## Qualification

`scripts/qualification_m74_distribution.py` statically verifies the production image names, immutable-tag guidance, persistence path, mirror/registry model, and absence of development image references from deployment definitions. Canonical CI runs this gate after M7.3.
