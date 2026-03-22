from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from email.message import Message
from http.client import HTTPMessage
from urllib import error as urllib_error
from urllib import request as urllib_request

from .data_sources import DEFAULT_FINGERPRINT_DATA_SOURCE, FingerprintDataSource
from .engine import Wappalyzer, extract_html_artifacts, get_default_wappalyzer
from .models import AnalysisResult, Technology
from .script_analysis import ScriptAnalysisOptions, fetch_external_script_contents
from .security import inspect_security_headers, is_security_technology

DEFAULT_USER_AGENT = "wappalyzer-pure/0.1.0"


def analyze_response(
    headers: Mapping[str, str | bytes | Sequence[str | bytes]],
    body: bytes | bytearray | memoryview | str,
    *,
    source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
    response_url: str | None = None,
    script_analysis: ScriptAnalysisOptions | None = None,
    script_timeout: float = 10.0,
    script_request_headers: Mapping[str, str] | None = None,
    script_opener: urllib_request.OpenerDirector | None = None,
    client: Wappalyzer | None = None,
) -> AnalysisResult:
    normalized_headers = normalize_headers(headers)
    body_bytes = _coerce_body(body)
    active_client = client or get_default_wappalyzer(source)
    active_script_analysis = script_analysis or ScriptAnalysisOptions()
    html_artifacts = None
    extra_script_contents: tuple[str, ...] = ()

    if active_script_analysis.fetch_enabled:
        if not response_url:
            raise ValueError(
                "response_url is required when external script fetching is enabled"
            )
        html_artifacts = extract_html_artifacts(body_bytes.decode("latin-1"))
        extra_script_contents = fetch_external_script_contents(
            page_url=response_url,
            script_sources=html_artifacts.script_sources,
            options=active_script_analysis,
            timeout=script_timeout,
            opener=script_opener,
            request_headers=script_request_headers,
        )

    raw_technologies = active_client.fingerprint_with_info(
        normalized_headers,
        body_bytes,
        html_artifacts=html_artifacts,
        extra_script_contents=extra_script_contents,
    )
    technologies = tuple(
        _build_technology(name, info) for name, info in raw_technologies.items()
    )
    security_headers = inspect_security_headers(normalized_headers)
    return AnalysisResult(
        technologies=technologies,
        security_headers=security_headers,
        body_length=len(body_bytes),
    )


def analyze_url(
    url: str,
    *,
    timeout: float = 10.0,
    request_headers: Mapping[str, str] | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
    opener: urllib_request.OpenerDirector | None = None,
    source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
    script_analysis: ScriptAnalysisOptions | None = None,
    client: Wappalyzer | None = None,
) -> AnalysisResult:
    headers = {"User-Agent": user_agent}
    if request_headers:
        headers.update({str(key): str(value) for key, value in request_headers.items()})

    active_opener = opener or urllib_request.build_opener()
    response = None
    try:
        request = urllib_request.Request(url, headers=headers)
        response = active_opener.open(request, timeout=timeout)
    except urllib_error.HTTPError as exc:
        response = exc

    if response is None:
        raise RuntimeError("failed to obtain an HTTP response")

    with response:
        response_body = response.read()
        response_headers = headers_from_http_message(response.headers)
        final_url = response.geturl()
        script_headers = dict(headers)
        script_headers.setdefault("Referer", final_url)
        result = analyze_response(
            response_headers,
            response_body,
            source=source,
            response_url=final_url,
            script_analysis=script_analysis,
            script_timeout=timeout,
            script_request_headers=script_headers,
            script_opener=active_opener,
            client=client,
        )
        return AnalysisResult(
            target_url=url,
            final_url=final_url,
            status_code=response.getcode(),
            technologies=result.technologies,
            security_headers=result.security_headers,
            body_length=result.body_length,
        )


def headers_from_http_message(
    message: HTTPMessage | Message[str, str],
) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for key, value in message.items():
        headers.setdefault(key, []).append(value)
    return headers


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
