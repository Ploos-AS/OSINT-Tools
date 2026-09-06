from osint_tools import server
from osint_tools.auth import hash_password

FIXTURES = [
    ("m62-admin", "M62 Admin", "m62-admin-password", "admin"),
    ("m62-owner", "M62 Owner", "m62-owner-password", "analyst"),
    ("m62-editor", "M62 Editor", "m62-editor-password", "analyst"),
    ("m62-viewer", "M62 Viewer", "m62-viewer-password", "viewer"),
    ("m62-outsider", "M62 Outsider", "m62-outsider-password", "analyst"),
]

if server.STORE.count_users() != 0:
    raise SystemExit("M6.2 browser fixture requires an empty database")

for username, display_name, password, role in FIXTURES:
    server.STORE.create_user(username, display_name, hash_password(password), role)

server.main()
