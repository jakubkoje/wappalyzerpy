from __future__ import annotations

from collections.abc import Mapping

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

SECURITY_HEADER_NAMES = (
    ("Content-Security-Policy", "content-security-policy"),
    ("Strict-Transport-Security", "strict-transport-security"),
    ("X-Frame-Options", "x-frame-options"),
    ("X-Content-Type-Options", "x-content-type-options"),
    ("Referrer-Policy", "referrer-policy"),
    ("Permissions-Policy", "permissions-policy"),
    ("Cross-Origin-Opener-Policy", "cross-origin-opener-policy"),
    ("Cross-Origin-Embedder-Policy", "cross-origin-embedder-policy"),
    ("Cross-Origin-Resource-Policy", "cross-origin-resource-policy"),
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


def inspect_security_headers(
    headers: Mapping[str, list[str]],
) -> tuple[SecurityHeaderStatus, ...]:
    normalized = {key.casefold(): list(values) for key, values in headers.items()}
    statuses = []
    for display_name, normalized_name in SECURITY_HEADER_NAMES:
        values = normalized.get(normalized_name, [])
        statuses.append(
            SecurityHeaderStatus(
                name=display_name,
                present=bool(values),
                value=", ".join(values) if values else None,
            )
        )
    return tuple(statuses)
