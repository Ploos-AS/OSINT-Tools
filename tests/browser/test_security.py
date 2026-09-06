"""M6.2 real-browser security qualification.

The browser dependency is optional for local development. Canonical CI installs
it and therefore treats a skip as a qualification failure at the shell gate.
"""
from __future__ import annotations
import os
import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import Page, expect

BASE_URL = os.environ.get("OSINT_TOOLS_BROWSER_BASE_URL")
pytestmark = pytest.mark.skipif(not BASE_URL, reason="browser qualification server not configured")


def login(page: Page, username: str, password: str) -> None:
    page.goto(f"{BASE_URL}/login")
    page.get_by_label("Username").fill(username)
    page.get_by_label("Password").fill(password)
    page.get_by_role("button", name="Login").click()
    page.wait_for_load_state("networkidle")


def test_login_logout_and_protected_navigation(page: Page) -> None:
    login(page, "m62-owner", "m62-owner-password")
    expect(page).not_to_have_url(f"{BASE_URL}/login")
    page.get_by_role("link", name="Logout").click()
    page.goto(f"{BASE_URL}/cases")
    expect(page).to_have_url(f"{BASE_URL}/login")


def test_hostile_case_name_is_rendered_as_text(page: Page) -> None:
    login(page, "m62-owner", "m62-owner-password")
    page.goto(f"{BASE_URL}/cases")
    hostile = '<img src=x onerror="window.__m62_xss=1">M62 hostile'
    page.get_by_label("Case name").fill(hostile)
    page.get_by_role("button", name="Create case").click()
    page.wait_for_load_state("networkidle")
    expect(page.get_by_text(hostile, exact=True)).to_be_visible()
    assert page.evaluate("() => window.__m62_xss") is None
