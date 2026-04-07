from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from urllib import request as urllib_request

from .antibot import enrich_anti_bot_findings_with_response_metadata
from .api import DEFAULT_USER_AGENT, analyze_response
from .artifacts import capture_timestamp_utc, normalize_artifact_capture_options
from .data_sources import DEFAULT_FINGERPRINT_DATA_SOURCE, FingerprintDataSource
from .engine import Wappalyzer, get_default_wappalyzer
from .fetching import (
    DEFAULT_BROWSER_USER_AGENT,
    FetchedResponse,
    FetchFailure,
    FetchHeaderProfile,
    FetchOptions,
    build_opener,
    build_request_headers,
    fetch_url,
)
from .models import (
    AnalysisResult,
    ArtifactCaptureOptions,
    ProbeObservation,
    ProbeResult,
)
from .script_analysis import ScriptAnalysisOptions


@dataclass(frozen=True, slots=True)
class ProbeOptions:
    repeat_request: bool = True
    follow_up_with_cookies: bool = True
    browser_like_request: bool = True
    browser_user_agent: str | None = DEFAULT_BROWSER_USER_AGENT


def probe_url(
    url: str,
    *,
    timeout: float = 10.0,
    request_headers: Mapping[str, str] | None = None,
    user_agent: str | None = DEFAULT_USER_AGENT,
    opener: urllib_request.OpenerDirector | None = None,
    source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
    script_analysis: ScriptAnalysisOptions | None = None,
    client: Wappalyzer | None = None,
    probe_options: ProbeOptions | None = None,
    capture_artifacts: bool | ArtifactCaptureOptions | None = None,
    fetch_options: FetchOptions | None = None,
) -> ProbeResult:
    options = probe_options or ProbeOptions()
    active_fetch_options = fetch_options or FetchOptions(timeout=timeout)
    active_opener = opener or build_opener(active_fetch_options)
    active_capture_options = normalize_artifact_capture_options(capture_artifacts)
    active_client = client or get_default_wappalyzer(source)
    observations: list[ProbeObservation] = []

    base_headers = _build_request_headers(
        request_headers=request_headers,
        user_agent=user_agent,
        fetch_options=active_fetch_options,
    )
    initial_response = _fetch_url(
        url,
        request_headers=base_headers,
        fetch_options=active_fetch_options,
        opener=active_opener,
    )
    initial_result = _analyze_fetched_response(
        initial_response,
        url=url,
        source=source,
        script_analysis=script_analysis,
        client=active_client,
        opener=active_opener,
        request_headers=base_headers,
        fetch_options=active_fetch_options,
        capture_artifacts=active_capture_options,
    )
    response_cookie_header = (
        None
        if isinstance(initial_response, FetchFailure)
        else _build_cookie_header(initial_response.headers)
    )
    response_cookie_names = (
        ()
        if isinstance(initial_response, FetchFailure)
        else _cookie_names_from_headers(initial_response.headers)
    )
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
            fetch_options=active_fetch_options,
            opener=active_opener,
        )
        repeat_result = _analyze_fetched_response(
            repeat_response,
            url=url,
            source=source,
            script_analysis=script_analysis,
            client=active_client,
            opener=active_opener,
            request_headers=base_headers,
            fetch_options=active_fetch_options,
            capture_artifacts=active_capture_options,
        )
        observations.append(
            _build_probe_observation(
                name="repeat",
                result=repeat_result,
                request_headers=base_headers,
                response_cookie_names=(
                    ()
                    if isinstance(repeat_response, FetchFailure)
                    else _cookie_names_from_headers(repeat_response.headers)
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
                fetch_options=active_fetch_options,
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
            fetch_options=active_fetch_options,
        )
        observations.append(
            _request_probe_observation(
                name="browser_like",
                url=url,
                request_headers=browser_headers,
                fetch_options=replace(
                    active_fetch_options,
                    header_profile=FetchHeaderProfile.BROWSER,
                ),
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
    fetch_options: FetchOptions,
    opener: urllib_request.OpenerDirector,
    source: FingerprintDataSource | str,
    script_analysis: ScriptAnalysisOptions | None,
    client: Wappalyzer | None,
    capture_artifacts: ArtifactCaptureOptions | None,
) -> ProbeObservation:
    response = _fetch_url(
        url,
        request_headers=request_headers,
        fetch_options=fetch_options,
        opener=opener,
    )
    result = _analyze_fetched_response(
        response,
        url=url,
        source=source,
        script_analysis=script_analysis,
        client=client,
        opener=opener,
        request_headers=request_headers,
        fetch_options=fetch_options,
        capture_artifacts=capture_artifacts,
    )
    return _build_probe_observation(
        name=name,
        result=result,
        request_headers=request_headers,
        response_cookie_names=(
            ()
            if isinstance(response, FetchFailure)
            else _cookie_names_from_headers(response.headers)
        ),
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
    user_agent: str | None,
    fetch_options: FetchOptions,
) -> dict[str, str]:
    return build_request_headers(
        request_headers=request_headers,
        user_agent=user_agent,
        options=fetch_options,
    )


def _build_browser_like_headers(
    *,
    request_headers: Mapping[str, str] | None,
    user_agent: str | None,
    fetch_options: FetchOptions,
) -> dict[str, str]:
    return build_request_headers(
        request_headers=request_headers,
        user_agent=user_agent,
        options=replace(fetch_options, header_profile=FetchHeaderProfile.BROWSER),
    )


def _fetch_url(
    url: str,
    *,
    request_headers: Mapping[str, str],
    fetch_options: FetchOptions,
    opener: urllib_request.OpenerDirector,
) -> FetchedResponse | FetchFailure:
    return fetch_url(
        url,
        request_headers=request_headers,
        options=fetch_options,
        opener=opener,
        accept_http_error_response=True,
    )


def _analyze_fetched_response(
    fetched: FetchedResponse | FetchFailure,
    *,
    url: str,
    source: FingerprintDataSource | str,
    script_analysis: ScriptAnalysisOptions | None,
    client: Wappalyzer | None,
    opener: urllib_request.OpenerDirector,
    request_headers: Mapping[str, str],
    fetch_options: FetchOptions,
    capture_artifacts: ArtifactCaptureOptions | None,
) -> AnalysisResult:
    active_client = client or get_default_wappalyzer(source)
    if isinstance(fetched, FetchFailure):
        return AnalysisResult(
            target_url=url,
            fetch_failure=fetched,
        )
    script_headers = dict(request_headers)
    script_headers.setdefault("Referer", fetched.final_url)
    result = analyze_response(
        fetched.headers,
        fetched.body,
        source=source,
        status_code=fetched.status_code,
        response_url=fetched.final_url,
        script_analysis=script_analysis,
        script_timeout=fetch_options.timeout,
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
        fetch_info=fetched.fetch_info,
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
