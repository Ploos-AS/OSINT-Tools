import html

from osint_tools import ui


def test_ui_escapes_hostile_case_file_and_evidence_values():
    hostile = '<script>alert(1)</script> "><svg/onload=alert(1)>'
    rendered = ui.page(hostile, ui.cases([{"id": 1, "name": hostile, "status": hostile, "updated_at": hostile}])).decode()
    assert hostile not in rendered
    assert html.escape(hostile, quote=True) in rendered
    assert "<script>alert(1)</script>" not in rendered


def test_file_page_distinguishes_not_scanned_and_escapes_metadata():
    file = {"id": 1, "case_id": 1, "original_filename": "../../etc/passwd", "size": 0, "detected_type": "<img src=x>", "extension": ".txt", "md5": "a", "sha1": "b", "sha256": "c"}
    rendered = ui.file_detail(file, {"data": {"filename": "<script>x</script>"}, "structured": []}, [], [], [])
    assert "Not scanned" in rendered
    assert "<img src=x>" not in rendered
    assert "&lt;img src=x&gt;" in rendered


def test_ui_shell_has_local_assets_and_security_language():
    rendered = ui.page("Cases", "<p>content</p>").decode()
    assert '/static/app.css' in rendered and '/static/app.js' in rendered
    assert 'lang="en"' in rendered
