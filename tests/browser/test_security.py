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
    assert outsider.locator("body").inner_text().lower().find("not found") >= 0
    owner_ctx.close(); outsider_ctx.close()


def test_global_viewer_ceiling_and_direct_grant(browser: Browser) -> None:
    owner_ctx, owner = fresh_page(browser, "m62-owner", "m62-owner-password")
    url = create_case(owner, "M62 viewer ceiling")
    grant = owner.locator('form[action$="/acl"]')
    grant.get_by_label("Principal ID").fill("4")
    grant.get_by_label("Access").select_option("editor")
    grant.get_by_role("button", name="Grant access").click()
    owner.wait_for_load_state("networkidle")
    viewer_ctx, viewer = fresh_page(browser, "m62-viewer", "m62-viewer-password")
    viewer.goto(url)
    expect(viewer.get_by_text("Effective access: viewer", exact=False)).to_be_visible()
    expect(viewer.locator('form[method="post"]')).to_have_count(0)
    owner_ctx.close(); viewer_ctx.close()


def test_hostile_case_name_is_rendered_as_text(page: Page) -> None:
    login(page, "m62-owner", "m62-owner-password")
    hostile = '<img src=x onerror="window.__m62_xss=1">M62 hostile'
    create_case(page, hostile)
    expect(page.get_by_text(hostile, exact=True)).to_be_visible()
    assert page.evaluate("() => typeof window.__m62_xss === 'undefined'") is True
