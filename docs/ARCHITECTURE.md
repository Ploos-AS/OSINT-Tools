# Architecture direction

The intended mature layout is a browser UI backed by a small server API and bounded workers/adapters. Local deterministic tools should not depend on third-party providers. Network providers are isolated behind adapters with explicit timeouts, rate limits, provenance and credential handling.

The case/pivot engine should consume normalized observations rather than provider-specific response formats. This lets a domain discovered through certificate transparency pivot through the same model as a domain entered manually.

SQLite is the standalone default. A storage interface should make PostgreSQL possible later without changing the investigation model.
