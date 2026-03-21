from __future__ import annotations

from wappalyzer_pure.security import get_security_header_names, inspect_security_headers


def test_get_security_header_names_loads_packaged_data() -> None:
    headers = get_security_header_names()

    assert "Strict-Transport-Security" in headers
    assert "Content-Security-Policy" in headers
    assert len(headers) == 9


def test_inspect_security_headers_uses_packaged_header_data() -> None:
    statuses = inspect_security_headers(
        {
            "Strict-Transport-Security": ["max-age=63072000"],
            "X-Frame-Options": ["DENY"],
        }
    )

    by_name = {status.name: status for status in statuses}
    assert by_name["Strict-Transport-Security"].present is True
    assert by_name["Strict-Transport-Security"].value == "max-age=63072000"
    assert by_name["X-Frame-Options"].present is True
    assert by_name["Content-Security-Policy"].present is False
