from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from urllib import error as urllib_error
from urllib import request as urllib_request

from .antibot import enrich_anti_bot_findings_with_response_metadata
from .api import DEFAULT_USER_AGENT, analyze_response, headers_from_http_message
from .artifacts import capture_timestamp_utc, normalize_artifact_capture_options
from .data_sources import DEFAULT_FINGERPRINT_DATA_SOURCE, FingerprintDataSource
from .engine import Wappalyzer, get_default_wappalyzer
from .models import (
    AnalysisResult,
    ArtifactCaptureOptions,
    ProbeObservation,
    ProbeResult,
)
from .script_analysis import ScriptAnalysisOptions

DEFAULT_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/134.0.0.0 Safari/537.36"
)
_BROWSER_HEADER_PROFILE = {
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
        "image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "max-age=0",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}


@dataclass(frozen=True, slots=True)
class ProbeOptions:
    repeat_request: bool = True
    follow_up_with_cookies: bool = True
    browser_like_request: bool = True
    browser_user_agent: str = DEFAULT_BROWSER_USER_AGENT


@dataclass(frozen=True, slots=True)
class _FetchedResponse:
    target_url: str
    final_url: str
    status_code: int | None
    headers: dict[str, list[str]]
    body: bytes


def probe_url(
    url: str,
    *,
    timeout: float = 10.0,
    request_headers: Mapping[str, str] | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
    opener: urllib_request.OpenerDirector | None = None,
    source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
    script_analysis: ScriptAnalysisOptions | None = None,
    client: Wappalyzer | None = None,
    probe_options: ProbeOptions | None = None,
    capture_artifacts: bool | ArtifactCaptureOptions | None = None,
) -> ProbeResult:
    options = probe_options or ProbeOptions()
    active_opener = opener or urllib_request.build_opener()
    active_capture_options = normalize_artifact_capture_options(capture_artifacts)
    active_client = client or get_default_wappalyzer(source)
    observations: list[ProbeObservation] = []

    base_headers = _build_request_headers(
        request_headers=request_headers,
        user_agent=user_agent,
    )
    initial_response = _fetch_url(
        url,
        request_headers=base_headers,
        timeout=timeout,
        opener=active_opener,
    )
    initial_result = _analyze_fetched_response(
        initial_response,
        source=source,
        script_analysis=script_analysis,
        client=active_client,
        opener=active_opener,
        request_headers=base_headers,
        timeout=timeout,
        capture_artifacts=active_capture_options,
    )
    response_cookie_header = _build_cookie_header(initial_response.headers)
    response_cookie_names = _cookie_names_from_headers(initial_response.headers)
    observations.append(
        _build_probe_observation(
            name="initial",
            result=initial_result,
            request_headers=base_headers,
            response_cookie_names=response_cookie_names,
        )
    )

    if options.repeat_request:
        repeat_response = _fetch_url(
            url,
            request_headers=base_headers,
            timeout=timeout,
            opener=active_opener,
        )
        repeat_result = _analyze_fetched_response(
            repeat_response,
            source=source,
            script_analysis=script_analysis,
            client=active_client,
            opener=active_opener,
            request_headers=base_headers,
            timeout=timeout,
            capture_artifacts=active_capture_options,
        )
        observations.append(
            _build_probe_observation(
                name="repeat",
                result=repeat_result,
                request_headers=base_headers,
                response_cookie_names=_cookie_names_from_headers(
                    repeat_response.headers
                ),
            )
        )

    if options.follow_up_with_cookies and response_cookie_header:
        cookie_headers = dict(base_headers)
        cookie_headers["Cookie"] = response_cookie_header
        observations.append(
            _request_probe_observation(
                name="cookie_follow_up",
                url=url,
                request_headers=cookie_headers,
                timeout=timeout,
                opener=active_opener,
                source=source,
                script_analysis=script_analysis,
                client=active_client,
                capture_artifacts=active_capture_options,
            )
        )

    if options.browser_like_request:
        browser_headers = _build_browser_like_headers(
            request_headers=request_headers,
            user_agent=options.browser_user_agent,
        )
        observations.append(
            _request_probe_observation(
                name="browser_like",
                url=url,
                request_headers=browser_headers,
                timeout=timeout,
                opener=active_opener,
                source=source,
                script_analysis=script_analysis,
                client=active_client,
                capture_artifacts=active_capture_options,
            )
        )

    return ProbeResult(observations=tuple(observations))


def _request_probe_observation(
    *,
    name: str,
    url: str,
    request_headers: dict[str, str],
    timeout: float,
    opener: urllib_request.OpenerDirector,
    source: FingerprintDataSource | str,
    script_analysis: ScriptAnalysisOptions | None,
    client: Wappalyzer | None,
    capture_artifacts: ArtifactCaptureOptions | None,
) -> ProbeObservation:
    response = _fetch_url(
        url,
        request_headers=request_headers,
        timeout=timeout,
        opener=opener,
    )
    result = _analyze_fetched_response(
        response,
        source=source,
        script_analysis=script_analysis,
        client=client,
        opener=opener,
        request_headers=request_headers,
        timeout=timeout,
        capture_artifacts=capture_artifacts,
    )
    return _build_probe_observation(
        name=name,
        result=result,
        request_headers=request_headers,
        response_cookie_names=_cookie_names_from_headers(response.headers),
    )


def _build_probe_observation(
    *,
    name: str,
    result: AnalysisResult,
    request_headers: Mapping[str, str],
    response_cookie_names: tuple[str, ...],
) -> ProbeObservation:
    request_cookie_names = _cookie_names_from_request_headers(request_headers)
    return ProbeObservation(
        name=name,
        result=result,
        request_headers=tuple(
            sorted(request_headers.items(), key=lambda item: item[0])
        ),
        request_cookie_names=request_cookie_names,
        response_cookie_names=response_cookie_names,
    )


def _build_request_headers(
    *,
    request_headers: Mapping[str, str] | None,
    user_agent: str,
) -> dict[str, str]:
    headers = {"User-Agent": user_agent}
    if request_headers:
        headers.update({str(key): str(value) for key, value in request_headers.items()})
    return headers


def _build_browser_like_headers(
    *,
    request_headers: Mapping[str, str] | None,
    user_agent: str,
) -> dict[str, str]:
    headers = dict(_BROWSER_HEADER_PROFILE)
    headers["User-Agent"] = user_agent
    if request_headers:
        headers.update({str(key): str(value) for key, value in request_headers.items()})
    return headers


def _fetch_url(
    url: str,
    *,
    request_headers: Mapping[str, str],
    timeout: float,
    opener: urllib_request.OpenerDirector,
) -> _FetchedResponse:
    response = None
    try:
        request = urllib_request.Request(url, headers=dict(request_headers))
        response = opener.open(request, timeout=timeout)
    except urllib_error.HTTPError as exc:
        response = exc

    if response is None:
        raise RuntimeError("failed to obtain an HTTP response")

    with response:
        return _FetchedResponse(
            target_url=url,
            final_url=response.geturl(),
            status_code=response.getcode(),
            headers=headers_from_http_message(response.headers),
            body=response.read(),
        )


def _analyze_fetched_response(
    fetched: _FetchedResponse,
    *,
    source: FingerprintDataSource | str,
    script_analysis: ScriptAnalysisOptions | None,
    client: Wappalyzer | None,
    opener: urllib_request.OpenerDirector,
    request_headers: Mapping[str, str],
    timeout: float,
    capture_artifacts: ArtifactCaptureOptions | None,
) -> AnalysisResult:
    active_client = client or get_default_wappalyzer(source)
    script_headers = dict(request_headers)
    script_headers.setdefault("Referer", fetched.final_url)
    result = analyze_response(
        fetched.headers,
        fetched.body,
        source=source,
        response_url=fetched.final_url,
        script_analysis=script_analysis,
        script_timeout=timeout,
        script_request_headers=script_headers,
        script_opener=opener,
        client=active_client,
        capture_artifacts=capture_artifacts,
    )
    anti_bot_findings = enrich_anti_bot_findings_with_response_metadata(
        result.anti_bot_findings,
        target_url=fetched.target_url,
        final_url=fetched.final_url,
        status_code=fetched.status_code,
        anti_bot_aliases=active_client.anti_bot_aliases,
    )
    artifacts = result.artifacts
    if artifacts is not None and artifacts.captured_at_utc is None:
        artifacts = replace(artifacts, captured_at_utc=capture_timestamp_utc())
    return AnalysisResult(
        target_url=fetched.target_url,
        final_url=fetched.final_url,
        status_code=fetched.status_code,
        technologies=result.technologies,
        anti_bot_findings=anti_bot_findings,
        security_headers=result.security_headers,
        body_length=result.body_length,
        artifacts=artifacts,
    )


def _cookie_names_from_headers(headers: Mapping[str, list[str]]) -> tuple[str, ...]:
    names: list[str] = []
    seen: set[str] = set()
    for value in headers.get("Set-Cookie", []) + headers.get("set-cookie", []):
        pair = value.split(";", 1)[0].strip()
        if "=" not in pair:
            continue
        name, _, _ = pair.partition("=")
        cookie_name = name.strip()
        if not cookie_name or cookie_name in seen:
            continue
        seen.add(cookie_name)
        names.append(cookie_name)
    return tuple(names)


def _cookie_names_from_request_headers(
    headers: Mapping[str, str],
) -> tuple[str, ...]:
    cookie_value = None
    for key, value in headers.items():
        if key.casefold() == "cookie":
            cookie_value = value
            break
    if not cookie_value:
        return ()

    names: list[str] = []
    seen: set[str] = set()
    for fragment in cookie_value.split(";"):
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


def _build_cookie_header(headers: Mapping[str, list[str]]) -> str | None:
    pairs: list[str] = []
    seen: set[str] = set()
    for value in headers.get("Set-Cookie", []) + headers.get("set-cookie", []):
        pair = value.split(";", 1)[0].strip()
        if "=" not in pair:
            continue
        name, _, _ = pair.partition("=")
        cookie_name = name.strip()
        if not cookie_name or cookie_name in seen:
            continue
        seen.add(cookie_name)
        pairs.append(pair)
    if not pairs:
        return None
    return "; ".join(pairs)
