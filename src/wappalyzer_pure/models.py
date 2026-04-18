from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Technology:
    raw_name: str
    name: str
    version: str | None = None
    description: str | None = None
    website: str | None = None
    cpe: str | None = None
    icon: str | None = None
    categories: tuple[str, ...] = ()
    security_relevant: bool = False

    @property
    def display_name(self) -> str:
        if self.version:
            return f"{self.name}:{self.version}"
        return self.name

    def to_dict(self) -> dict[str, object]:
        return {
            "raw_name": self.raw_name,
            "name": self.name,
            "version": self.version,
            "display_name": self.display_name,
            "description": self.description,
            "website": self.website,
            "cpe": self.cpe,
            "icon": self.icon,
            "categories": list(self.categories),
            "security_relevant": self.security_relevant,
        }


@dataclass(frozen=True, slots=True)
class SecurityHeaderStatus:
    name: str
    present: bool
    value: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "present": self.present,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class AntiBotEvidence:
    source: str
    indicator: str
    matched_value: str | None = None
    artifact: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "indicator": self.indicator,
            "matched_value": self.matched_value,
            "artifact": self.artifact,
        }


@dataclass(frozen=True, slots=True)
class AntiBotFinding:
    vendor: str
    score: int
    confidence: str
    products: tuple[str, ...] = ()
    behaviors: tuple[str, ...] = ()
    evidence: tuple[AntiBotEvidence, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "vendor": self.vendor,
            "score": self.score,
            "confidence": self.confidence,
            "products": list(self.products),
            "behaviors": list(self.behaviors),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class ArtifactCaptureOptions:
    body_excerpt_chars: int = 256
    captured_at_utc: str | None = None

    def __post_init__(self) -> None:
        if self.body_excerpt_chars < 0:
            raise ValueError("body_excerpt_chars must be zero or greater")


@dataclass(frozen=True, slots=True)
class CapturedHeader:
    name: str
    values: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "values": list(self.values),
        }


@dataclass(frozen=True, slots=True)
class BrowserSignals:
    cookie_header: str | None = None
    script_sources: tuple[str, ...] = ()
    iframe_sources: tuple[str, ...] = ()
    resource_urls: tuple[str, ...] = ()
    runtime_markers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ResponseArtifacts:
    captured_at_utc: str | None = None
    headers: tuple[CapturedHeader, ...] = ()
    set_cookie_values: tuple[str, ...] = ()
    script_sources: tuple[str, ...] = ()
    iframe_sources: tuple[str, ...] = ()
    fetched_script_urls: tuple[str, ...] = ()
    resource_urls: tuple[str, ...] = ()
    runtime_markers: tuple[str, ...] = ()
    browser_cookie_names: tuple[str, ...] = ()
    body_sha256: str | None = None
    body_excerpt: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "captured_at_utc": self.captured_at_utc,
            "headers": [header.to_dict() for header in self.headers],
            "set_cookie_values": list(self.set_cookie_values),
            "script_sources": list(self.script_sources),
            "iframe_sources": list(self.iframe_sources),
            "fetched_script_urls": list(self.fetched_script_urls),
            "resource_urls": list(self.resource_urls),
            "runtime_markers": list(self.runtime_markers),
            "browser_cookie_names": list(self.browser_cookie_names),
            "body_sha256": self.body_sha256,
            "body_excerpt": self.body_excerpt,
        }


@dataclass(frozen=True, slots=True)
class FetchInfo:
    attempts: int
    partial_response: bool
    header_profile: str
    tls_mode: str
    transport: str = "http"
    browser: str | None = None
    wait_until: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "attempts": self.attempts,
            "partial_response": self.partial_response,
            "header_profile": self.header_profile,
            "tls_mode": self.tls_mode,
            "transport": self.transport,
            "browser": self.browser,
            "wait_until": self.wait_until,
        }


@dataclass(frozen=True, slots=True)
class FetchFailure:
    category: str
    error_type: str
    message: str
    retryable: bool
    attempts: int

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "error_type": self.error_type,
            "message": self.message,
            "retryable": self.retryable,
            "attempts": self.attempts,
        }


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    target_url: str | None = None
    final_url: str | None = None
    status_code: int | None = None
    technologies: tuple[Technology, ...] = ()
    anti_bot_findings: tuple[AntiBotFinding, ...] = ()
    security_headers: tuple[SecurityHeaderStatus, ...] = ()
    body_length: int = 0
    artifacts: ResponseArtifacts | None = None
    fetch_info: FetchInfo | None = None
    fetch_failure: FetchFailure | None = None

    @property
    def security_technologies(self) -> tuple[Technology, ...]:
        return tuple(
            technology
            for technology in self.technologies
            if technology.security_relevant
        )

    @property
    def ok(self) -> bool:
        return self.fetch_failure is None

    def to_dict(self, *, security_only: bool = False) -> dict[str, object]:
        technologies = (
            self.security_technologies if security_only else self.technologies
        )
        return {
            "target_url": self.target_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "body_length": self.body_length,
            "technologies": [technology.to_dict() for technology in technologies],
            "anti_bot_findings": [
                finding.to_dict() for finding in self.anti_bot_findings
            ],
            "security_headers": [header.to_dict() for header in self.security_headers],
            "artifacts": None if self.artifacts is None else self.artifacts.to_dict(),
            "fetch_info": (
                None if self.fetch_info is None else self.fetch_info.to_dict()
            ),
            "fetch_failure": (
                None if self.fetch_failure is None else self.fetch_failure.to_dict()
            ),
        }


@dataclass(frozen=True, slots=True)
class ProbeObservation:
    name: str
    result: AnalysisResult
    request_headers: tuple[tuple[str, str], ...] = ()
    request_cookie_names: tuple[str, ...] = ()
    response_cookie_names: tuple[str, ...] = ()

    @property
    def redirected(self) -> bool:
        return bool(
            self.result.target_url
            and self.result.final_url
            and self.result.target_url != self.result.final_url
        )

    @property
    def challenge_observed(self) -> bool:
        for finding in self.result.anti_bot_findings:
            if any(
                behavior in {"challenge", "captcha"} for behavior in finding.behaviors
            ):
                return True
        return False

    @property
    def throttled(self) -> bool:
        if self.result.status_code == 429:
            return True
        for finding in self.result.anti_bot_findings:
            if "rate_limit" in finding.behaviors:
                return True
        return False

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "redirected": self.redirected,
            "challenge_observed": self.challenge_observed,
            "throttled": self.throttled,
            "request_headers": [
                {"name": name, "value": value} for name, value in self.request_headers
            ],
            "request_cookie_names": list(self.request_cookie_names),
            "response_cookie_names": list(self.response_cookie_names),
            "result": self.result.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ProbeResult:
    observations: tuple[ProbeObservation, ...] = ()

    @property
    def challenge_observed(self) -> bool:
        return any(observation.challenge_observed for observation in self.observations)

    @property
    def throttled(self) -> bool:
        return any(observation.throttled for observation in self.observations)

    @property
    def vendors(self) -> tuple[str, ...]:
        values: list[str] = []
        seen: set[str] = set()
        for observation in self.observations:
            for finding in observation.result.anti_bot_findings:
                if finding.vendor in seen:
                    continue
                seen.add(finding.vendor)
                values.append(finding.vendor)
        return tuple(values)

    def to_dict(self) -> dict[str, object]:
        return {
            "challenge_observed": self.challenge_observed,
            "throttled": self.throttled,
            "vendors": list(self.vendors),
            "observations": [item.to_dict() for item in self.observations],
        }
