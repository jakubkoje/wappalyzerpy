from __future__ import annotations

import json
from collections.abc import Mapping
from functools import lru_cache
from importlib import resources

from .exceptions import DataLoadError
from .models import SecurityHeaderStatus

SECURITY_KEYWORDS = (
    "security",
    "authentication",
    "identity",
    "single sign-on",
    "sso",
    "captcha",
    "firewall",
    "proxy",
    "reverse proxy",
    "cdn",
    "ssl",
    "tls",
    "bot management",
    "ddos",
    "zero trust",
    "access management",
    "network appliance",
)


def is_security_technology(
    *,
    name: str,
    categories: tuple[str, ...],
    description: str | None,
) -> bool:
    haystacks = [name.casefold(), *(category.casefold() for category in categories)]
    if description:
        haystacks.append(description.casefold())
    return any(keyword in text for text in haystacks for keyword in SECURITY_KEYWORDS)


@lru_cache
def get_security_header_names() -> tuple[str, ...]:
    package = "wappalyzer_pure.data"
    try:
        payload = json.loads(
            resources.files(package)
            .joinpath("security/security_headers_data.json")
            .read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        raise DataLoadError(f"failed to decode security header data: {exc}") from exc

    headers = payload.get("headers")
    if not isinstance(headers, list):
        raise DataLoadError("security header data is missing the headers list")

    result: list[str] = []
    for value in headers:
        if not isinstance(value, str) or not value:
            raise DataLoadError(
                f"security header names must be non-empty strings, got {value!r}"
            )
        result.append(value)
    return tuple(result)


def inspect_security_headers(
    headers: Mapping[str, list[str]],
) -> tuple[SecurityHeaderStatus, ...]:
    normalized = {key.casefold(): list(values) for key, values in headers.items()}
    statuses = []
    for display_name in get_security_header_names():
        normalized_name = display_name.casefold()
        values = normalized.get(normalized_name, [])
        statuses.append(
            SecurityHeaderStatus(
                name=display_name,
                present=bool(values),
                value=", ".join(values) if values else None,
            )
        )
    return tuple(statuses)
