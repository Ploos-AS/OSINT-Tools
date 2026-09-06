"""M6.2 real-browser security qualification."""
from __future__ import annotations
import os
import pytest
pytest.importorskip("playwright.sync_api")
from playwright.sync_api import Browser, Page, expect

BASE_URL = os.environ.get("OSINT_TOOLS_BROWSER_BASE_URL")
pytestmark = pytest.mark.skipif(not BASE_URL, reason="browser qualification server not configured")


def login(page: Page, username: str, password: str) -> None:
    page.goto(f"{BASE_URL}/login")
    page.get_by_label("Username").fill(username)
    page.get_by_label("Password").fill(password)
    page.get_by_role("button", name="Sign in").click()
    page.wait_for_url(f"{BASE_URL}/cases")


def fresh_page(browser: Browser, username: str, password: str):
    context = browser.new_context()
    page = context.new_page()
    login(page, username, password)
    return context, page


def create_case(page: Page, name: str) -> str:
    page.goto(f"{BASE_URL}/cases")
    page.get_by_label("Name").fill(name)
    page.get_by_role("button", name="Create case").click()
    page.wait_for_load_state("networkidle")
    return page.url


def grant_access(owner: Page, principal_type: str, principal_id: int, access: str) -> None:
    form = owner.locator('form[action$="/acl"]')
    form.locator('select[name="principal_type"]').select_option(principal_type)
    form.locator('input[name="principal_id"]').fill(str(principal_id))
    form.locator('select[name="access"]').select_option(access)
    form.get_by_role("button", name="Grant access").click()
    owner.wait_for_load_state("networkidle")


def test_login_logout_and_protected_navigation(page: Page) -> None:
    login(page, "m62-owner", "m62-owner-password")
    response = page.evaluate("""async () => fetch('/api/v1/auth/logout',{method:'POST',headers:{'X-CSRF-Token':sessionStorage.getItem('osint_csrf')}}).then(r=>r.status)""")
    assert response == 200
    page.goto(f"{BASE_URL}/cases")
    expect(page).to_have_url(f"{BASE_URL}/login")


def test_case_ownership_and_outsider_isolation(browser: Browser) -> None:
    owner_ctx, owner = fresh_page(browser, "m62-owner", "m62-owner-password")
    url = create_case(owner, "M62 ownership")
    expect(owner.get_by_text("Owner: M62 Owner", exact=False)).to_be_visible()
    outsider_ctx, outsider = fresh_page(browser, "m62-outsider", "m62-outsider-password")
    outsider.goto(url)
    expect(outsider.get_by_text("M62 ownership", exact=True)).to_have_count(0)
    assert "not found" in outsider.locator("body").inner_text().lower()
    owner_ctx.close(); outsider_ctx.close()


def test_direct_viewer_grant_is_read_only(browser: Browser) -> None:
    owner_ctx, owner = fresh_page(browser, "m62-owner", "m62-owner-password")
    url = create_case(owner, "M62 direct viewer")
    grant_access(owner, "user", 5, "viewer")
    viewer_ctx, viewer = fresh_page(browser, "m62-outsider", "m62-outsider-password")
    viewer.goto(url)
    expect(viewer.get_by_text("Effective access: viewer", exact=False)).to_be_visible()
    expect(viewer.locator('form[method="post"]')).to_have_count(0)
    owner_ctx.close(); viewer_ctx.close()


def test_direct_editor_grant_then_revoke(browser: Browser) -> None:
    owner_ctx, owner = fresh_page(browser, "m62-owner", "m62-owner-password")
    url = create_case(owner, "M62 editor revoke")
    grant_access(owner, "user", 3, "editor")
    editor_ctx, editor = fresh_page(browser, "m62-editor", "m62-editor-password")
    editor.goto(url)
    expect(editor.get_by_text("Effective access: editor", exact=False)).to_be_visible()
    expect(editor.get_by_role("button", name="Add target")).to_be_visible()
    owner.goto(url)
    owner.locator('form[action*="/acl/"]').get_by_role("button", name="Revoke grant").click()
    owner.wait_for_load_state("networkidle")
    editor.reload()
    assert "not found" in editor.locator("body").inner_text().lower()
    owner_ctx.close(); editor_ctx.close()


def test_ownership_transfer_moves_owner_controls(browser: Browser) -> None:
    owner_ctx, owner = fresh_page(browser, "m62-owner", "m62-owner-password")
    url = create_case(owner, "M62 transfer")
    transfer = owner.locator('form[action$="/owner"]')
    transfer.get_by_label("New owner user ID").fill("3")
    action = transfer.get_attribute("action")
    assert action is not None
    with owner.expect_response(lambda response: response.url == f"{BASE_URL}{action}" and response.request.method == "PATCH") as response_info:
        transfer.get_by_role("button", name="Assign owner").click()
    assert response_info.value.status == 200
    owner.reload()
    assert "not found" in owner.locator("body").inner_text().lower()
    editor_ctx, editor = fresh_page(browser, "m62-editor", "m62-editor-password")
    editor.goto(url)
    expect(editor.get_by_text("Effective access: owner", exact=False)).to_be_visible()
    expect(editor.get_by_role("button", name="Assign owner")).to_be_visible()
    owner_ctx.close(); editor_ctx.close()


def test_team_access_disappears_after_membership_removal(browser: Browser) -> None:
    admin_ctx, admin = fresh_page(browser, "m62-admin", "m62-admin-password")
    admin.goto(f"{BASE_URL}/admin/teams")
    create = admin.locator('form[action="/api/v1/admin/teams"]')
    create.get_by_label("Name").fill("M62 responders")
    create.get_by_role("button", name="Create team").click()
    admin.wait_for_load_state("networkidle")
    team = admin.get_by_role("heading", name="M62 responders").locator("xpath=..")
    team.get_by_label("User ID").fill("3")
    team.get_by_role("button", name="Add member").click()
    admin.wait_for_load_state("networkidle")

    owner_ctx, owner = fresh_page(browser, "m62-owner", "m62-owner-password")
    url = create_case(owner, "M62 team access")
    grant_access(owner, "team", 1, "editor")
    editor_ctx, editor = fresh_page(browser, "m62-editor", "m62-editor-password")
    editor.goto(url)
    expect(editor.get_by_text("Effective access: editor", exact=False)).to_be_visible()

    admin.goto(f"{BASE_URL}/admin/teams")
    admin.locator('form[action$="/members/3"]').get_by_role("button", name="Remove member").click()
    admin.wait_for_load_state("networkidle")
    editor.reload()
    assert "not found" in editor.locator("body").inner_text().lower()
    admin_ctx.close(); owner_ctx.close(); editor_ctx.close()


def test_global_viewer_ceiling_over_editor_grant(browser: Browser) -> None:
    owner_ctx, owner = fresh_page(browser, "m62-owner", "m62-owner-password")
    url = create_case(owner, "M62 viewer ceiling")
    grant_access(owner, "user", 4, "editor")
    viewer_ctx, viewer = fresh_page(browser, "m62-viewer", "m62-viewer-password")
    viewer.goto(url)
    expect(viewer.get_by_text("Effective access: viewer", exact=False)).to_be_visible()
    expect(viewer.locator('form[method="post"]')).to_have_count(0)
    owner_ctx.close(); viewer_ctx.close()


def test_csrf_missing_header_is_rejected(page: Page) -> None:
    login(page, "m62-owner", "m62-owner-password")
    status = page.evaluate("""async () => fetch('/api/v1/cases',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'csrf should fail'})}).then(r=>r.status)""")
    assert status == 403


def test_hostile_names_render_as_text(browser: Browser) -> None:
    owner_ctx, owner = fresh_page(browser, "m62-owner", "m62-owner-password")
    hostile_case = '<img src=x onerror="window.__m62_case=1">M62 hostile case'
    create_case(owner, hostile_case)
    expect(owner.get_by_text(hostile_case, exact=True)).to_be_visible()
    assert owner.evaluate("() => typeof window.__m62_case === 'undefined'") is True

    admin_ctx, admin = fresh_page(browser, "m62-admin", "m62-admin-password")
    admin.goto(f"{BASE_URL}/admin/teams")
    hostile_team = '<svg onload="window.__m62_team=1">M62 hostile team</svg>'
    create = admin.locator('form[action="/api/v1/admin/teams"]')
    create.get_by_label("Name").fill(hostile_team)
    create.get_by_role("button", name="Create team").click()
    admin.wait_for_load_state("networkidle")
    expect(admin.get_by_text(hostile_team, exact=True)).to_be_visible()
    assert admin.evaluate("() => typeof window.__m62_team === 'undefined'") is True

    hostile_user = '<img src=x onerror="window.__m62_user=1">M62 hostile user'
    status = admin.evaluate("""async (name) => fetch('/api/v1/admin/users/5',{method:'PATCH',headers:{'Content-Type':'application/json','X-CSRF-Token':sessionStorage.getItem('osint_csrf')},body:JSON.stringify({display_name:name})}).then(r=>r.status)""", hostile_user)
    assert status == 200
    admin.reload()
    owner_ctx.close(); admin_ctx.close()
