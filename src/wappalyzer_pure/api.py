from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from email.message import Message
from http.client import HTTPMessage
from urllib import request as urllib_request

from .antibot import (
    enrich_anti_bot_findings_with_response_metadata,
    inspect_anti_bot_findings,
)
from .artifacts import (
    build_response_artifacts,
    capture_timestamp_utc,
    normalize_artifact_capture_options,
)
from .data_sources import DEFAULT_FINGERPRINT_DATA_SOURCE, FingerprintDataSource
from .engine import Wappalyzer, extract_html_artifacts, get_default_wappalyzer
from .fetching import (
    DEFAULT_BROWSER_USER_AGENT,
    FetchFailure,
    FetchOptions,
    build_opener,
    build_request_headers,
    fetch_url,
)
from .fetching import (
    headers_from_http_message as _headers_from_http_message,
)
from .models import AnalysisResult, ArtifactCaptureOptions, Technology
from .script_analysis import ScriptAnalysisOptions, fetch_external_scripts
from .security import inspect_security_headers, is_security_technology

DEFAULT_USER_AGENT = DEFAULT_BROWSER_USER_AGENT


def analyze_response(
    headers: Mapping[str, str | bytes | Sequence[str | bytes]],
    body: bytes | bytearray | memoryview | str,
    *,
    source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
    status_code: int | None = None,
    response_url: str | None = None,
    script_analysis: ScriptAnalysisOptions | None = None,
    script_timeout: float = 10.0,
    script_request_headers: Mapping[str, str] | None = None,
    script_opener: urllib_request.OpenerDirector | None = None,
    client: Wappalyzer | None = None,
    capture_artifacts: bool | ArtifactCaptureOptions | None = None,
) -> AnalysisResult:
    normalized_headers = normalize_headers(headers)
    body_bytes = _coerce_body(body)
    active_client = client or get_default_wappalyzer(source)
    active_script_analysis = script_analysis or ScriptAnalysisOptions()
    active_capture_options = normalize_artifact_capture_options(capture_artifacts)
    body_text = body_bytes.decode("latin-1")
    html_artifacts = extract_html_artifacts(body_text)
    extra_script_contents: tuple[str, ...] = ()
    fetched_script_urls: tuple[str, ...] = ()

    if active_script_analysis.fetch_enabled:
        if not response_url:
            raise ValueError(
                "response_url is required when external script fetching is enabled"
            )
        fetched_scripts = fetch_external_scripts(
            page_url=response_url,
            script_sources=html_artifacts.script_sources,
            options=active_script_analysis,
            timeout=script_timeout,
            opener=script_opener,
            request_headers=script_request_headers,
        )
        fetched_script_urls = fetched_scripts.urls
        extra_script_contents = fetched_scripts.contents

    raw_technologies = active_client.fingerprint_with_info(
        normalized_headers,
        body_bytes,
        html_artifacts=html_artifacts,
        extra_script_contents=extra_script_contents,
    )
    technologies = tuple(
        _build_technology(name, info) for name, info in raw_technologies.items()
    )
    anti_bot_findings = inspect_anti_bot_findings(
        headers=normalized_headers,
        body=body_bytes,
        technologies=technologies,
        status_code=status_code,
        script_sources=html_artifacts.script_sources,
        script_contents=html_artifacts.inline_scripts + extra_script_contents,
        anti_bot_catalog=active_client.anti_bot_catalog,
        anti_bot_aliases=active_client.anti_bot_aliases,
    )
    security_headers = inspect_security_headers(normalized_headers)
    return AnalysisResult(
        technologies=technologies,
        anti_bot_findings=anti_bot_findings,
        security_headers=security_headers,
        body_length=len(body_bytes),
        artifacts=(
            build_response_artifacts(
                headers=normalized_headers,
                body=body_bytes,
                html_artifacts=html_artifacts,
                fetched_script_urls=fetched_script_urls,
                capture_options=active_capture_options,
            )
            if active_capture_options is not None
            else None
        ),
    )


def analyze_url(
    url: str,
    *,
    timeout: float = 10.0,
    request_headers: Mapping[str, str] | None = None,
    user_agent: str | None = None,
    opener: urllib_request.OpenerDirector | None = None,
    source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
    script_analysis: ScriptAnalysisOptions | None = None,
    client: Wappalyzer | None = None,
    capture_artifacts: bool | ArtifactCaptureOptions | None = None,
    fetch_options: FetchOptions | None = None,
) -> AnalysisResult:
    active_fetch_options = fetch_options or FetchOptions(timeout=timeout)
    headers = build_request_headers(
        request_headers=request_headers,
        user_agent=user_agent,
        options=active_fetch_options,
    )
    active_capture_options = normalize_artifact_capture_options(capture_artifacts)
    active_client = client or get_default_wappalyzer(source)
    active_opener = opener or build_opener(active_fetch_options)
    fetched = fetch_url(
        url,
        request_headers=headers,
        options=active_fetch_options,
        opener=active_opener,
        accept_http_error_response=True,
    )
    if isinstance(fetched, FetchFailure):
        return AnalysisResult(
            target_url=url,
            fetch_failure=fetched,
        )

    script_headers = dict(headers)
    script_headers.setdefault("Referer", fetched.final_url)
    result = analyze_response(
        fetched.headers,
        fetched.body,
        source=source,
        status_code=fetched.status_code,
        response_url=fetched.final_url,
        script_analysis=script_analysis,
        script_timeout=active_fetch_options.timeout,
        script_request_headers=script_headers,
        script_opener=active_opener,
        client=active_client,
        capture_artifacts=active_capture_options,
    )
    anti_bot_findings = enrich_anti_bot_findings_with_response_metadata(
        result.anti_bot_findings,
        target_url=url,
        final_url=fetched.final_url,
        status_code=fetched.status_code,
        anti_bot_aliases=active_client.anti_bot_aliases,
    )
    artifacts = result.artifacts
    if (
        artifacts is not None
        and active_capture_options is not None
        and artifacts.captured_at_utc is None
    ):
        artifacts = replace(artifacts, captured_at_utc=capture_timestamp_utc())
    return AnalysisResult(
        target_url=url,
        final_url=fetched.final_url,
        status_code=fetched.status_code,
        technologies=result.technologies,
        anti_bot_findings=anti_bot_findings,
        security_headers=result.security_headers,
        body_length=result.body_length,
        artifacts=artifacts,
        fetch_info=fetched.fetch_info,
    )


def headers_from_http_message(
    message: HTTPMessage | Message[str, str],
) -> dict[str, list[str]]:
    return _headers_from_http_message(message)


def normalize_headers(
    headers: Mapping[str, str | bytes | Sequence[str | bytes]],
) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for key, value in headers.items():
        if value is None:
            continue
        normalized[str(key)] = _coerce_header_values(value)
    return normalized


def _coerce_header_values(value: str | bytes | Sequence[str | bytes]) -> list[str]:
    if isinstance(value, (str, bytes)):
        return [_coerce_text(value)]

    if isinstance(value, Iterable):
        coerced = [_coerce_text(item) for item in value]
        if coerced:
            return coerced

    raise TypeError(f"unsupported header value: {value!r}")


def _coerce_text(value: str | bytes) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1")
    return str(value)


def _coerce_body(body: bytes | bytearray | memoryview | str) -> bytes:
    if isinstance(body, bytes):
        return body
    if isinstance(body, bytearray):
        return bytes(body)
    if isinstance(body, memoryview):
        return body.tobytes()
    if isinstance(body, str):
        return body.encode("utf-8")
    raise TypeError(f"unsupported body type: {type(body)!r}")


def _build_technology(name: str, info: object) -> Technology:
    from .engine import AppInfo

    if not isinstance(info, AppInfo):
        raise TypeError(f"unexpected app info payload: {info!r}")

    raw_name = name
    clean_name, version = _split_version(name)
    description = info.description
    categories = info.categories
    return Technology(
        raw_name=raw_name,
        name=clean_name,
        version=version,
        description=description,
        website=info.website,
        cpe=info.cpe,
        icon=info.icon,
        categories=categories,
        security_relevant=is_security_technology(
            name=clean_name,
            categories=categories,
            description=description,
        ),
    )


def _split_version(value: str) -> tuple[str, str | None]:
    if ":" not in value:
        return value, None
    name, version = value.rsplit(":", 1)
    if not name or not version:
        return value, None
    return name, version
