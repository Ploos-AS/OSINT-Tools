# Browser security tests

This directory is reserved for the bounded M6.2 real-browser security harness.

The harness must implement the scenarios in `docs/M6_2_BROWSER_QUALIFICATION.md` against a real authenticated OSINT Tools server. Browser tooling is test-only and must not enter the production OCI image.

Implementation order:

1. fixture server + deterministic users;
2. login/logout and ownership isolation;
3. direct viewer/editor grant and revoke;
4. ownership transfer;
5. team-derived access and membership removal;
6. global viewer ceiling;
7. CSRF rejection;
8. hostile-name DOM escaping;
9. named integration in `scripts/qualify.sh` and canonical GitHub Actions.

Do not use arbitrary sleeps for synchronization and do not persist secrets in screenshots, traces or CI artifacts.
