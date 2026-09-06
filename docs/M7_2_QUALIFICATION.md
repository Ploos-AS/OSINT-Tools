# M7.2 Backup, Restore and Upgrade Qualification

M7.2 turns the M7 release-data contract into a mandatory executable gate.

## Gate

`scripts/qualification_m72_backup_restore.py` runs against the same `osint-tools:dev` image produced by canonical qualification and proves both upgrade compatibility and cold backup/restore behavior.

The gate first re-runs the immutable M6.0 schema-8 fixture migration through the current image. This retains the existing evidence that schema 8 is upgraded to schema 9 on startup, legacy evidence and authentication state survive, and the migrated store remains valid after restart.

It then creates a fresh authenticated current-schema deployment containing:

- administrator and analyst users;
- a team and team membership;
- a team-derived editor ACL;
- a case and note;
- uploaded evidence stored in the content-addressed file store.

The application is stopped before backup. The complete persistent `/data` tree is archived using a helper invocation of the application image, restored into a new empty persistent root, and the original root is not mounted again.

After restore the gate verifies:

1. schema version 9 and `PRAGMA foreign_key_check`;
2. application version/milestone continuity;
3. administrator and analyst authentication;
4. case and note persistence;
5. team membership and effective team-derived editor access;
6. file database association and the exact uploaded bytes by SHA-256;
7. successful application restart with the restored ACL and file still accessible.

The gate fails closed: archive, restore, migration, authentication, authorization, database-integrity or evidence-byte failures produce a non-zero exit status.

## CI integration

GitHub Actions runs this as the named `M7.2 backup restore upgrade` step after canonical qualification has built and exercised the OCI image. The M6.2 real-browser security gate remains separate.

## Scope

This qualifies the supported cold/quiesced backup contract documented in `BACKUP_RESTORE.md` and the forward schema-upgrade contract documented in `UPGRADE.md`. Online SQLite backup, downgrade migrations and distributed/HA storage remain out of scope for v1.0.
