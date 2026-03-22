from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256

from .engine import HTMLArtifacts
from .models import ArtifactCaptureOptions, CapturedHeader, ResponseArtifacts


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
    default_captured_at_utc: str | None = None,
) -> ResponseArtifacts:
    return ResponseArtifacts(
        captured_at_utc=(
            capture_options.captured_at_utc
            if capture_options.captured_at_utc is not None
            else default_captured_at_utc
        ),
        headers=_normalize_headers(headers),
        set_cookie_values=_set_cookie_values(headers),
        script_sources=html_artifacts.script_sources,
        fetched_script_urls=fetched_script_urls,
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


def _body_excerpt(*, body: bytes, body_excerpt_chars: int) -> str | None:
    if body_excerpt_chars <= 0:
        return None
    return body.decode("latin-1")[:body_excerpt_chars]
