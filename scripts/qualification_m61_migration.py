#!/usr/bin/env python3
"""Deterministic schema-8 fixture; generated only in isolated qualification data.

Use the immutable baseline's schema source to avoid reverse-migrating schema 9.
The caller supplies baseline storage.py via a temporary, read-only file.
"""
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

def fixture(path, source=None):
    if source is None:
        source=subprocess.check_output(['git','show','2f3356a5118abc0d5d64670194e06504d1961076:src/osint_tools/storage.py'])
    with tempfile.TemporaryDirectory() as temp:
        module_path=Path(temp)/'schema8.py'; module_path.write_bytes(source)
        spec=importlib.util.spec_from_file_location('schema8_fixture',module_path); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        assert module.SCHEMA_VERSION==8
        store=module.Store(path)
        from osint_tools.auth import hash_password
        store.create_user('migrationadmin','Migration admin',hash_password('qualification-migration-sentinel'),'admin')
        store.create_case('M61 legacy schema8','Evidence must survive')
        store.add_target(1,'domain','legacy.example','legacy.example')
        store.add_audit('fixture_preserved','success',1,metadata={'fixture':True})
        store.create_session('fixture-session-hash',1,'fixture-csrf-hash','2999-01-01T00:00:00+00:00')
        with store.connect() as conn: assert conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0]=='8'

if __name__=='__main__': fixture(Path(sys.argv[1]),Path(sys.argv[2]).read_bytes() if len(sys.argv)>2 else None)
