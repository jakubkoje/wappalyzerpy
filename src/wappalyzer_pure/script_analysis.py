from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import Enum
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from .fetching import (
    FetchFailure,
    FetchHeaderProfile,
    FetchOptions,
    build_opener,
    fetch_url,
)


class ScriptFetchPolicy(str, Enum):
    OFF = "off"
    SAME_ORIGIN = "same-origin"


@dataclass(frozen=True, slots=True)
class ScriptAnalysisOptions:
    fetch_policy: ScriptFetchPolicy = ScriptFetchPolicy.OFF
    max_external_scripts: int = 8
    max_bytes_per_script: int = 256_000
    max_total_script_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        if self.max_external_scripts < 0:
            raise ValueError("max_external_scripts must be zero or greater")
        if self.max_bytes_per_script <= 0:
            raise ValueError("max_bytes_per_script must be greater than zero")
        if self.max_total_script_bytes <= 0:
            raise ValueError("max_total_script_bytes must be greater than zero")

    @property
    def fetch_enabled(self) -> bool:
        return (
            self.fetch_policy is not ScriptFetchPolicy.OFF
            and self.max_external_scripts > 0
            and self.max_total_script_bytes > 0
        )


@dataclass(frozen=True, slots=True)
class FetchedScripts:
    urls: tuple[str, ...] = ()
    contents: tuple[str, ...] = ()


def fetch_external_script_contents(
    *,
    page_url: str,
    script_sources: Iterable[str],
    options: ScriptAnalysisOptions,
    timeout: float,
    opener: urllib_request.OpenerDirector | None = None,
    request_headers: Mapping[str, str] | None = None,
    fetch_options: FetchOptions | None = None,
) -> tuple[str, ...]:
    return fetch_external_scripts(
        page_url=page_url,
        script_sources=script_sources,
        options=options,
        timeout=timeout,
        opener=opener,
        request_headers=request_headers,
        fetch_options=fetch_options,
    ).contents


def fetch_external_scripts(
    *,
    page_url: str,
    script_sources: Iterable[str],
    options: ScriptAnalysisOptions,
    timeout: float,
    opener: urllib_request.OpenerDirector | None = None,
    request_headers: Mapping[str, str] | None = None,
    fetch_options: FetchOptions | None = None,
) -> FetchedScripts:
    if not options.fetch_enabled:
        return FetchedScripts()

    candidate_urls = _resolve_script_urls(
        page_url=page_url,
        script_sources=script_sources,
        options=options,
    )
    if not candidate_urls:
        return FetchedScripts()

    active_fetch_options = fetch_options or FetchOptions(
        timeout=timeout,
        header_profile=FetchHeaderProfile.LIBRARY,
    )
    if active_fetch_options.timeout != timeout:
        active_fetch_options = replace(active_fetch_options, timeout=timeout)
    active_opener = opener or build_opener(active_fetch_options)
    total_bytes = 0
    fetched_urls: list[str] = []
    contents: list[str] = []

    for script_url in candidate_urls:
        remaining_bytes = options.max_total_script_bytes - total_bytes
        if remaining_bytes <= 0:
            break

        per_script_limit = min(options.max_bytes_per_script, remaining_bytes)
        if per_script_limit <= 0:
            break

        fetched = fetch_url(
            script_url,
            request_headers=_normalize_request_headers(request_headers),
            options=active_fetch_options,
            opener=active_opener,
            accept_http_error_response=False,
            read_limit=per_script_limit,
        )
        if isinstance(fetched, FetchFailure):
            continue
        payload = fetched.body
        if not payload or len(payload) > per_script_limit:
            continue

        total_bytes += len(payload)
        fetched_urls.append(fetched.final_url)
        contents.append(payload.decode("latin-1"))

    return FetchedScripts(urls=tuple(fetched_urls), contents=tuple(contents))


def _resolve_script_urls(
    *,
    page_url: str,
    script_sources: Iterable[str],
    options: ScriptAnalysisOptions,
) -> tuple[str, ...]:
    resolved_urls: list[str] = []
    seen: set[str] = set()
    page_origin = _origin(page_url)
    if page_origin is None:
        return ()

    for source in script_sources:
        if len(resolved_urls) >= options.max_external_scripts:
            break

        resolved_url = urllib_parse.urljoin(page_url, source)
        origin = _origin(resolved_url)
        if origin is None:
            continue
        if (
            options.fetch_policy is ScriptFetchPolicy.SAME_ORIGIN
            and origin != page_origin
        ):
            continue
        if resolved_url in seen:
            continue
        seen.add(resolved_url)
        resolved_urls.append(resolved_url)

    return tuple(resolved_urls)


def _origin(url: str) -> tuple[str, str, int] | None:
    parsed = urllib_parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, parsed.hostname, port


def _normalize_request_headers(
    headers: Mapping[str, str] | None,
) -> dict[str, str]:
    if not headers:
        return {}
    return {str(key): str(value) for key, value in headers.items()}
