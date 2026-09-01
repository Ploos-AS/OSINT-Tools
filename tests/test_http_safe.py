import pytest

from osint_tools.core import _public_host


def test_private_ipv4_is_blocked():
    with pytest.raises(ValueError):
        _public_host("127.0.0.1")


def test_private_ipv6_is_blocked():
    with pytest.raises(ValueError):
        _public_host("::1")
