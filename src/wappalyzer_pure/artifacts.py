from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256

from .engine import HTMLArtifacts
from .models import (
    ArtifactCaptureOptions,
    BrowserSignals,
    CapturedHeader,
    ResponseArtifacts,
)


def normalize_artifact_capture_options(
    capture_artifacts: bool | ArtifactCaptureOptions | None,
) -> ArtifactCaptureOptions | None:
    if capture_artifacts is None or capture_artifacts is False:
        return None
    if capture_artifacts is True:
        return ArtifactCaptureOptions()
    return capture_artifacts


def build_response_artifacts(
    *,
    headers: Mapping[str, list[str]],
    body: bytes,
    html_artifacts: HTMLArtifacts,
    fetched_script_urls: tuple[str, ...],
    capture_options: ArtifactCaptureOptions,
    browser_signals: BrowserSignals | None = None,
    default_captured_at_utc: str | None = None,
) -> ResponseArtifacts:
    active_browser_signals = browser_signals or BrowserSignals()
    return ResponseArtifacts(
        captured_at_utc=(
            capture_options.captured_at_utc
            if capture_options.captured_at_utc is not None
            else default_captured_at_utc
        ),
        headers=_normalize_headers(headers),
        set_cookie_values=_set_cookie_values(headers),
        script_sources=html_artifacts.script_sources,
        iframe_sources=html_artifacts.iframe_sources,
        fetched_script_urls=fetched_script_urls,
        resource_urls=active_browser_signals.resource_urls,
        runtime_markers=active_browser_signals.runtime_markers,
        browser_cookie_names=_browser_cookie_names(active_browser_signals.cookie_header),
        body_sha256=sha256(body).hexdigest(),
        body_excerpt=_body_excerpt(
            body=body,
            body_excerpt_chars=capture_options.body_excerpt_chars,
        ),
    )


def capture_timestamp_utc() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_headers(
    headers: Mapping[str, list[str]],
) -> tuple[CapturedHeader, ...]:
    return tuple(
        CapturedHeader(name=name, values=tuple(values))
        for name, values in sorted(
            (
                (header_name.casefold(), values)
                for header_name, values in headers.items()
            ),
            key=lambda item: item[0],
        )
    )


def _set_cookie_values(headers: Mapping[str, list[str]]) -> tuple[str, ...]:
    values: list[str] = []
    for header_name, header_values in headers.items():
        if header_name.casefold() != "set-cookie":
            continue
        values.extend(header_values)
    return tuple(values)


def _browser_cookie_names(cookie_header: str | None) -> tuple[str, ...]:
    if not cookie_header:
        return ()
    names: list[str] = []
    seen: set[str] = set()
    for fragment in cookie_header.split(";"):
        pair = fragment.strip()
        if "=" not in pair:
            continue
        name, _, _ = pair.partition("=")
        cookie_name = name.strip()
        if not cookie_name or cookie_name in seen:
            continue
        seen.add(cookie_name)
        names.append(cookie_name)
    return tuple(names)


def _body_excerpt(*, body: bytes, body_excerpt_chars: int) -> str | None:
    if body_excerpt_chars <= 0:
        return None
    return body.decode("latin-1")[:body_excerpt_chars]
