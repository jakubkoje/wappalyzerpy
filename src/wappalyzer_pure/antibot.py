from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from .antibot_aliases import AntiBotAliasCatalog
from .antibot_catalog import AntiBotTechnologyCatalogEntry
from .exceptions import DataLoadError
from .models import AntiBotEvidence, AntiBotFinding, Technology

_DEFAULT_EVIDENCE_WEIGHTS = {
    "technology": 3,
    "cookie": 3,
    "body": 3,
    "header": 1,
    "header_value": 1,
    "security_header": 3,
    "script_source": 3,
    "iframe_source": 3,
    "resource_url": 3,
    "script_content": 3,
    "runtime_marker": 3,
    "status_code": 1,
    "status_heuristic": 3,
    "redirect": 1,
}
_SUSPICIOUS_STATUS_CODES = {401, 403, 429, 503}
_POLICY_HEADER_NAMES = (
    "content-security-policy",
    "content-security-policy-report-only",
)
_MINIMAL_BLOCK_TEXT_LIMIT = 256
_SNIPPET_RADIUS = 48


@dataclass(frozen=True, slots=True)
class _ConfidenceThresholds:
    medium: int = 3
    high: int = 5


@dataclass(frozen=True, slots=True)
class _CalibrationConfig:
    evidence_weights: Mapping[str, int]
    default_confidence_thresholds: _ConfidenceThresholds


@dataclass(frozen=True, slots=True)
class _SignalRule:
    technology_names: tuple[str, ...] = ()
    cookie_names: tuple[str, ...] = ()
    cookie_prefixes: tuple[str, ...] = ()
    header_names: tuple[str, ...] = ()
    header_value_contains: tuple[tuple[str, tuple[str, ...]], ...] = ()
    body_substrings: tuple[str, ...] = ()
    script_source_substrings: tuple[str, ...] = ()
    iframe_source_substrings: tuple[str, ...] = ()
    resource_url_substrings: tuple[str, ...] = ()
    script_content_substrings: tuple[str, ...] = ()
    runtime_markers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _BehaviorRule:
    name: str
    min_score: int
    signals: _SignalRule


@dataclass(frozen=True, slots=True)
class _VendorRule:
    name: str
    min_score: int
    signals: _SignalRule
    confidence_thresholds: _ConfidenceThresholds
    behaviors: tuple[_BehaviorRule, ...] = ()


@dataclass(frozen=True, slots=True)
class _SecurityHeaderFingerprint:
    product_name: str
    substrings: tuple[str, ...]
    header_names: tuple[str, ...] = _POLICY_HEADER_NAMES


@dataclass(frozen=True, slots=True)
class _DetectionContext:
    detected_technologies: tuple[Technology, ...]
    technologies: Mapping[str, Technology]
    cookies: Mapping[str, tuple[str, str]]
    headers: Mapping[str, tuple[str, ...]]
    raw_body_text: str
    body_text: str
    script_sources: tuple[str, ...]
    iframe_sources: tuple[str, ...]
    resource_urls: tuple[str, ...]
    script_contents: tuple[str, ...]
    runtime_markers: tuple[str, ...]
    status_code: int | None


@dataclass(slots=True)
class _AccumulatedFinding:
    vendor_name: str
    behaviors: list[str]
    products: list[str]
    evidence: list[AntiBotEvidence]


@dataclass(frozen=True, slots=True)
class _TechnologyFindingCandidate:
    vendor_name: str
    products: tuple[str, ...]
    behaviors: tuple[str, ...]
    evidence: tuple[AntiBotEvidence, ...]


_SECURITY_HEADER_FINGERPRINTS = (
    _SecurityHeaderFingerprint(
        product_name="reCAPTCHA",
        substrings=(
            "www.google.com/recaptcha",
            "recaptcha.net",
            "recaptcha",
        ),
    ),
    _SecurityHeaderFingerprint(
        product_name="hCaptcha",
        substrings=("hcaptcha.com", "hcaptcha"),
    ),
    _SecurityHeaderFingerprint(
        product_name="GeeTest",
        substrings=("geetest.com", "geetest"),
    ),
    _SecurityHeaderFingerprint(
        product_name="Cloudflare Turnstile",
        substrings=("challenges.cloudflare.com/turnstile", "cf-turnstile"),
    ),
    _SecurityHeaderFingerprint(
        product_name="DataDome",
        substrings=("captcha-delivery.com", "ct.datadome.co", "datadome"),
    ),
    _SecurityHeaderFingerprint(
        product_name="PerimeterX",
        substrings=(
            "client.a.pxi.pub",
            "pxi.pub",
            "px-cdn.net",
            "px-cloud.net",
            "pxchk.net",
            "perimeterx.net",
            "perimeterx",
        ),
    ),
    _SecurityHeaderFingerprint(
        product_name="Kasada",
        substrings=("kpsdk", "kasada"),
    ),
)


def inspect_anti_bot_findings(
    *,
    headers: Mapping[str, list[str]],
    body: bytes,
    technologies: tuple[Technology, ...],
    status_code: int | None = None,
    script_sources: tuple[str, ...] = (),
    iframe_sources: tuple[str, ...] = (),
    resource_urls: tuple[str, ...] = (),
    script_contents: tuple[str, ...] = (),
    runtime_markers: tuple[str, ...] = (),
    request_cookie_header: str | None = None,
    anti_bot_catalog: Mapping[str, AntiBotTechnologyCatalogEntry] | None = None,
    anti_bot_aliases: AntiBotAliasCatalog | None = None,
) -> tuple[AntiBotFinding, ...]:
    context = _build_detection_context(
        headers=headers,
        body=body,
        technologies=technologies,
        script_sources=script_sources,
        iframe_sources=iframe_sources,
        resource_urls=resource_urls,
        script_contents=script_contents,
        runtime_markers=runtime_markers,
        status_code=status_code,
        request_cookie_header=request_cookie_header,
    )
    accumulated: dict[str, _AccumulatedFinding] = {}

    for vendor in _load_vendor_rules():
        vendor_evidence = _match_signals(vendor.signals, context)
        vendor_score = _score_evidence(vendor_evidence)
        if vendor_score < vendor.min_score:
            continue

        matched_behaviors: list[str] = []
        combined_evidence = list(vendor_evidence)
        for behavior in vendor.behaviors:
            behavior_evidence = _match_signals(behavior.signals, context)
            behavior_score = _score_evidence(behavior_evidence)
            if behavior_score < behavior.min_score:
                continue
            matched_behaviors.append(behavior.name)
            combined_evidence.extend(behavior_evidence)

        _merge_finding_candidate(
            accumulated,
            vendor_name=_canonical_vendor_name(vendor.name, anti_bot_aliases),
            products=(),
            behaviors=tuple(matched_behaviors),
            evidence=_deduplicate_evidence(combined_evidence),
        )

    for candidate in _derive_security_header_finding_candidates(
        context,
        anti_bot_catalog=anti_bot_catalog,
        anti_bot_aliases=anti_bot_aliases,
    ):
        _merge_finding_candidate(
            accumulated,
            vendor_name=candidate.vendor_name,
            products=candidate.products,
            behaviors=candidate.behaviors,
            evidence=list(candidate.evidence),
        )

    for candidate in _derive_technology_finding_candidates(
        context.detected_technologies,
        anti_bot_catalog=anti_bot_catalog,
        anti_bot_aliases=anti_bot_aliases,
    ):
        _merge_finding_candidate(
            accumulated,
            vendor_name=candidate.vendor_name,
            products=candidate.products,
            behaviors=candidate.behaviors,
            evidence=list(candidate.evidence),
        )

    for candidate in _derive_status_heuristic_finding_candidates(
        context,
        anti_bot_aliases=anti_bot_aliases,
    ):
        _merge_finding_candidate(
            accumulated,
            vendor_name=candidate.vendor_name,
            products=candidate.products,
            behaviors=candidate.behaviors,
            evidence=list(candidate.evidence),
        )

    findings = [
        _build_finding(
            vendor_name=item.vendor_name,
            products=tuple(item.products),
            behaviors=tuple(item.behaviors),
            evidence=_deduplicate_evidence(item.evidence),
            anti_bot_aliases=anti_bot_aliases,
        )
        for item in accumulated.values()
    ]
    findings.sort(key=lambda item: (-item.score, item.vendor.casefold()))
    return tuple(findings)


def enrich_anti_bot_findings_with_response_metadata(
    findings: tuple[AntiBotFinding, ...],
    *,
    target_url: str | None,
    final_url: str | None,
    status_code: int | None,
    anti_bot_aliases: AntiBotAliasCatalog | None = None,
) -> tuple[AntiBotFinding, ...]:
    if not findings:
        return ()

    enriched: list[AntiBotFinding] = []
    redirected = bool(target_url and final_url and target_url != final_url)
    for finding in findings:
        evidence = list(finding.evidence)
        if status_code in _SUSPICIOUS_STATUS_CODES:
            evidence.append(
                AntiBotEvidence(
                    source="status_code",
                    indicator="http_status",
                    matched_value=str(status_code),
                    artifact=f"HTTP {status_code}",
                )
            )
        if redirected and target_url is not None and final_url is not None:
            evidence.append(
                AntiBotEvidence(
                    source="redirect",
                    indicator="final_url",
                    matched_value=final_url,
                    artifact=f"{target_url} -> {final_url}",
                )
            )
        enriched.append(
            _build_finding(
                vendor_name=finding.vendor,
                products=finding.products,
                behaviors=finding.behaviors,
                evidence=_deduplicate_evidence(evidence),
                anti_bot_aliases=anti_bot_aliases,
            )
        )
    return tuple(enriched)


def _derive_technology_finding_candidates(
    technologies: tuple[Technology, ...],
    *,
    anti_bot_catalog: Mapping[str, AntiBotTechnologyCatalogEntry] | None,
    anti_bot_aliases: AntiBotAliasCatalog | None = None,
) -> tuple[_TechnologyFindingCandidate, ...]:
    if not anti_bot_catalog:
        return ()
    candidates: list[_TechnologyFindingCandidate] = []
    seen: set[str] = set()
    for technology in technologies:
        marker = technology.raw_name.casefold()
        if marker in seen:
            continue
        seen.add(marker)
        candidate = _derive_technology_finding_candidate(
            technology,
            anti_bot_catalog=anti_bot_catalog,
            anti_bot_aliases=anti_bot_aliases,
        )
        if candidate is None:
            continue
        candidates.append(candidate)
    return tuple(candidates)


def _derive_technology_finding_candidate(
    technology: Technology,
    *,
    anti_bot_catalog: Mapping[str, AntiBotTechnologyCatalogEntry],
    anti_bot_aliases: AntiBotAliasCatalog | None = None,
) -> _TechnologyFindingCandidate | None:
    entry = anti_bot_catalog.get(technology.name.casefold())
    if entry is None:
        entry = anti_bot_catalog.get(technology.raw_name.casefold())
    if entry is None:
        return None

    canonical_vendor = _canonical_vendor_name(entry.vendor, anti_bot_aliases)
    canonical_product = technology.name
    if anti_bot_aliases is not None:
        product = anti_bot_aliases.canonicalize_product(
            entry.name,
            vendor=entry.vendor,
        )
        canonical_vendor = product.canonical_vendor
        canonical_product = product.canonical_name

    return _TechnologyFindingCandidate(
        vendor_name=canonical_vendor,
        products=(canonical_product,),
        behaviors=entry.behaviors,
        evidence=(
            AntiBotEvidence(
                source="technology",
                indicator=technology.name.casefold(),
                matched_value=technology.name,
                artifact=technology.raw_name,
            ),
        ),
    )


def _merge_finding_candidate(
    findings: dict[str, _AccumulatedFinding],
    *,
    vendor_name: str,
    products: tuple[str, ...],
    behaviors: tuple[str, ...],
    evidence: list[AntiBotEvidence],
) -> None:
    existing = findings.get(vendor_name)
    if existing is None:
        findings[vendor_name] = _AccumulatedFinding(
            vendor_name=vendor_name,
            behaviors=list(behaviors),
            products=list(products),
            evidence=list(evidence),
        )
        return

    existing.behaviors = _merge_string_values(existing.behaviors, behaviors)
    existing.products = _merge_string_values(existing.products, products)
    existing.evidence.extend(evidence)


def _merge_string_values(
    current: list[str],
    new_values: tuple[str, ...],
) -> list[str]:
    merged = list(current)
    seen = set(current)
    for value in new_values:
        if value in seen:
            continue
        seen.add(value)
        merged.append(value)
    return merged


def _build_detection_context(
    *,
    headers: Mapping[str, list[str]],
    body: bytes,
    technologies: tuple[Technology, ...],
    script_sources: tuple[str, ...],
    iframe_sources: tuple[str, ...],
    resource_urls: tuple[str, ...],
    script_contents: tuple[str, ...],
    runtime_markers: tuple[str, ...],
    status_code: int | None,
    request_cookie_header: str | None,
) -> _DetectionContext:
    normalized_headers = {
        key.casefold(): tuple(str(value) for value in values)
        for key, values in headers.items()
    }
    raw_body_text = body.decode("latin-1")
    return _DetectionContext(
        detected_technologies=technologies,
        technologies=_build_technology_lookup(technologies),
        cookies=_extract_cookie_artifacts(
            normalized_headers,
            request_cookie_header=request_cookie_header,
        ),
        headers=normalized_headers,
        raw_body_text=raw_body_text,
        body_text=raw_body_text.casefold(),
        script_sources=script_sources,
        iframe_sources=iframe_sources,
        resource_urls=resource_urls,
        script_contents=script_contents,
        runtime_markers=runtime_markers,
        status_code=status_code,
    )


def _build_technology_lookup(
    technologies: tuple[Technology, ...],
) -> dict[str, Technology]:
    lookup: dict[str, Technology] = {}
    for technology in technologies:
        lookup.setdefault(technology.name.casefold(), technology)
        lookup.setdefault(technology.raw_name.casefold(), technology)
    return lookup


def _extract_cookie_artifacts(
    headers: Mapping[str, tuple[str, ...]],
    *,
    request_cookie_header: str | None,
) -> dict[str, tuple[str, str]]:
    cookies: dict[str, tuple[str, str]] = {}
    for header_name, values in headers.items():
        if header_name == "set-cookie":
            for value in values:
                pair = value.split(";", 1)[0].strip()
                if "=" not in pair:
                    continue
                name, _, _ = pair.partition("=")
                cookie_name = name.strip()
                if not cookie_name:
                    continue
                cookies.setdefault(cookie_name.casefold(), (cookie_name, value))
            continue
        if header_name != "cookie":
            continue
        for value in values:
            for fragment in value.split(";"):
                pair = fragment.strip()
                if "=" not in pair:
                    continue
                name, _, _ = pair.partition("=")
                cookie_name = name.strip()
                if not cookie_name:
                    continue
                cookies.setdefault(cookie_name.casefold(), (cookie_name, pair))
    if request_cookie_header:
        for fragment in request_cookie_header.split(";"):
            pair = fragment.strip()
            if "=" not in pair:
                continue
            name, _, _ = pair.partition("=")
            cookie_name = name.strip()
            if not cookie_name:
                continue
            cookies.setdefault(cookie_name.casefold(), (cookie_name, pair))
    return cookies


def _match_signals(
    rule: _SignalRule,
    context: _DetectionContext,
) -> list[AntiBotEvidence]:
    evidence: list[AntiBotEvidence] = []

    for technology_name in rule.technology_names:
        technology = context.technologies.get(technology_name)
        if technology is None:
            continue
        evidence.append(
            AntiBotEvidence(
                source="technology",
                indicator=technology_name,
                matched_value=technology.name,
                artifact=technology.raw_name,
            )
        )

    for cookie_name in rule.cookie_names:
        actual = context.cookies.get(cookie_name)
        if actual is None:
            continue
        actual_name, artifact = actual
        evidence.append(
            AntiBotEvidence(
                source="cookie",
                indicator=cookie_name,
                matched_value=actual_name,
                artifact=artifact,
            )
        )

    for cookie_prefix in rule.cookie_prefixes:
        for normalized_name, (actual_name, artifact) in context.cookies.items():
            if not normalized_name.startswith(cookie_prefix):
                continue
            evidence.append(
                AntiBotEvidence(
                    source="cookie",
                    indicator=cookie_prefix,
                    matched_value=actual_name,
                    artifact=artifact,
                )
            )

    for header_name in rule.header_names:
        values = context.headers.get(header_name)
        if not values:
            continue
        evidence.append(
            AntiBotEvidence(
                source="header",
                indicator=header_name,
                matched_value=header_name,
                artifact=_header_artifact(header_name, values[0]),
            )
        )

    for header_name, substrings in rule.header_value_contains:
        values = context.headers.get(header_name, ())
        if not values:
            continue
        for substring in substrings:
            matched_value = _find_header_value(values, substring)
            if matched_value is None:
                continue
            evidence.append(
                AntiBotEvidence(
                    source="header_value",
                    indicator=header_name,
                    matched_value=matched_value,
                    artifact=_header_artifact(header_name, matched_value),
                )
            )

    for substring in rule.body_substrings:
        matched_value, artifact = _find_text_artifact(
            context.raw_body_text,
            context.body_text,
            substring,
        )
        if matched_value is None:
            continue
        evidence.append(
            AntiBotEvidence(
                source="body",
                indicator=substring,
                matched_value=matched_value,
                artifact=artifact,
            )
        )

    for substring in rule.script_source_substrings:
        matched_value = _find_source_value(context.script_sources, substring)
        if matched_value is None:
            continue
        evidence.append(
            AntiBotEvidence(
                source="script_source",
                indicator=substring,
                matched_value=matched_value,
                artifact=matched_value,
            )
        )

    for substring in rule.iframe_source_substrings:
        matched_value = _find_source_value(context.iframe_sources, substring)
        if matched_value is None:
            continue
        evidence.append(
            AntiBotEvidence(
                source="iframe_source",
                indicator=substring,
                matched_value=matched_value,
                artifact=matched_value,
            )
        )

    for substring in rule.resource_url_substrings:
        matched_value = _find_source_value(context.resource_urls, substring)
        if matched_value is None:
            continue
        evidence.append(
            AntiBotEvidence(
                source="resource_url",
                indicator=substring,
                matched_value=matched_value,
                artifact=matched_value,
            )
        )

    for substring in rule.script_content_substrings:
        matched_value, artifact = _find_text_artifact_in_many(
            context.script_contents,
            substring,
        )
        if matched_value is None:
            continue
        evidence.append(
            AntiBotEvidence(
                source="script_content",
                indicator=substring,
                matched_value=matched_value,
                artifact=artifact,
            )
        )

    for marker in rule.runtime_markers:
        matched_value = _find_runtime_marker(context.runtime_markers, marker)
        if matched_value is None:
            continue
        evidence.append(
            AntiBotEvidence(
                source="runtime_marker",
                indicator=marker,
                matched_value=matched_value,
                artifact=matched_value,
            )
        )

    return evidence


def _find_header_value(values: tuple[str, ...], substring: str) -> str | None:
    for value in values:
        if substring in value.casefold():
            return value
    return None


def _header_artifact(name: str, value: str) -> str:
    return f"{name}: {value}"


def _find_source_value(
    values: tuple[str, ...],
    substring: str,
) -> str | None:
    for source in values:
        if substring in source.casefold():
            return source
    return None


def _find_runtime_marker(
    runtime_markers: tuple[str, ...],
    marker: str,
) -> str | None:
    for item in runtime_markers:
        if item == marker:
            return item
    return None


def _find_text_artifact(
    raw_text: str,
    folded_text: str,
    substring: str,
) -> tuple[str | None, str | None]:
    index = folded_text.find(substring)
    if index < 0:
        return None, None
    end = index + len(substring)
    matched_value = raw_text[index:end]
    snippet_start = max(0, index - _SNIPPET_RADIUS)
    snippet_end = min(len(raw_text), end + _SNIPPET_RADIUS)
    artifact = raw_text[snippet_start:snippet_end]
    return matched_value, artifact


def _find_text_artifact_in_many(
    values: tuple[str, ...],
    substring: str,
) -> tuple[str | None, str | None]:
    for value in values:
        matched_value, artifact = _find_text_artifact(
            value,
            value.casefold(),
            substring,
        )
        if matched_value is not None:
            return matched_value, artifact
    return None, None


def _derive_security_header_finding_candidates(
    context: _DetectionContext,
    *,
    anti_bot_catalog: Mapping[str, AntiBotTechnologyCatalogEntry] | None,
    anti_bot_aliases: AntiBotAliasCatalog | None = None,
) -> tuple[_TechnologyFindingCandidate, ...]:
    candidates: list[_TechnologyFindingCandidate] = []
    seen: set[str] = set()

    for fingerprint in _SECURITY_HEADER_FINGERPRINTS:
        if fingerprint.product_name.casefold() in seen:
            continue
        match = _find_security_header_match(context, fingerprint)
        if match is None:
            continue
        header_name, matched_value, artifact = match
        candidates.append(
            _build_named_finding_candidate(
                vendor_name=fingerprint.product_name,
                product_name=fingerprint.product_name,
                evidence=AntiBotEvidence(
                    source="security_header",
                    indicator=header_name,
                    matched_value=matched_value,
                    artifact=artifact,
                ),
                anti_bot_catalog=anti_bot_catalog,
                anti_bot_aliases=anti_bot_aliases,
            )
        )
        seen.add(fingerprint.product_name.casefold())

    return tuple(candidates)


def _find_security_header_match(
    context: _DetectionContext,
    fingerprint: _SecurityHeaderFingerprint,
) -> tuple[str, str, str] | None:
    for header_name in fingerprint.header_names:
        values = context.headers.get(header_name, ())
        if not values:
            continue
        for value in values:
            lowered = value.casefold()
            for substring in fingerprint.substrings:
                if substring not in lowered:
                    continue
                matched_value, _ = _find_text_artifact(value, lowered, substring)
                if matched_value is None:
                    continue
                return header_name, matched_value, _header_artifact(header_name, value)
    return None


def _derive_status_heuristic_finding_candidates(
    context: _DetectionContext,
    *,
    anti_bot_aliases: AntiBotAliasCatalog | None = None,
) -> tuple[_TechnologyFindingCandidate, ...]:
    if context.status_code != 403:
        return ()
    if not _has_generic_akamai_edge_signal(context):
        return ()

    return (
        _build_named_finding_candidate(
            vendor_name="Akamai",
            product_name=None,
            evidence=AntiBotEvidence(
                source="status_heuristic",
                indicator="akamai_edge_block",
                matched_value="Akamai",
                artifact="HTTP 403 with minimal body and Akamai edge fingerprints",
            ),
            anti_bot_catalog=None,
            anti_bot_aliases=anti_bot_aliases,
        ),
    )


def _build_named_finding_candidate(
    *,
    vendor_name: str,
    product_name: str | None,
    evidence: AntiBotEvidence,
    anti_bot_catalog: Mapping[str, AntiBotTechnologyCatalogEntry] | None,
    anti_bot_aliases: AntiBotAliasCatalog | None = None,
) -> _TechnologyFindingCandidate:
    behaviors: tuple[str, ...] = ()
    products: tuple[str, ...] = ()
    canonical_vendor = _canonical_vendor_name(vendor_name, anti_bot_aliases)

    if product_name is not None:
        catalog_entry = None
        if anti_bot_catalog is not None:
            catalog_entry = anti_bot_catalog.get(product_name.casefold())
        if catalog_entry is not None:
            vendor_name = catalog_entry.vendor
            product_name = catalog_entry.name
            behaviors = catalog_entry.behaviors
        if anti_bot_aliases is not None:
            product = anti_bot_aliases.canonicalize_product(
                product_name,
                vendor=vendor_name,
            )
            canonical_vendor = product.canonical_vendor
            products = (product.canonical_name,)
        else:
            canonical_vendor = vendor_name
            products = (product_name,)

    return _TechnologyFindingCandidate(
        vendor_name=canonical_vendor,
        products=products,
        behaviors=behaviors,
        evidence=(evidence,),
    )


def _looks_like_minimal_block_page(raw_body_text: str) -> bool:
    stripped = raw_body_text.strip()
    if not stripped:
        return True
    stripped = re.sub(
        r"<script\b[^>]*>.*?</script>",
        " ",
        stripped,
        flags=re.I | re.S,
    )
    stripped = re.sub(
        r"<style\b[^>]*>.*?</style>",
        " ",
        stripped,
        flags=re.I | re.S,
    )
    visible_text = re.sub(r"<[^>]+>", " ", stripped)
    normalized_text = " ".join(visible_text.split()).casefold()
    if not normalized_text:
        return True
    return len(normalized_text) <= _MINIMAL_BLOCK_TEXT_LIMIT


def _has_generic_akamai_edge_signal(context: _DetectionContext) -> bool:
    for technology in context.detected_technologies:
        if technology.name.casefold() == "akamai":
            return True

    if "x-akamai-transformed" in context.headers or "akamai-grn" in context.headers:
        return True

    for header_name, values in context.headers.items():
        if header_name.startswith("x-akamai-"):
            return True
        if header_name != "server":
            continue
        if any("akamai" in value.casefold() for value in values):
            return True

    return False


def _score_evidence(evidence: list[AntiBotEvidence]) -> int:
    weights = _load_calibration_config().evidence_weights
    return sum(weights.get(item.source, 0) for item in evidence)


def _deduplicate_evidence(
    evidence: list[AntiBotEvidence],
) -> list[AntiBotEvidence]:
    deduplicated: list[AntiBotEvidence] = []
    seen: set[tuple[str, str, str | None, str | None]] = set()
    for item in evidence:
        key = (item.source, item.indicator, item.matched_value, item.artifact)
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(item)
    return deduplicated


def _extract_products(
    evidence: list[AntiBotEvidence],
) -> tuple[str, ...]:
    products: list[str] = []
    seen: set[str] = set()
    for item in evidence:
        if item.source != "technology" or item.matched_value is None:
            continue
        if item.matched_value in seen:
            continue
        seen.add(item.matched_value)
        products.append(item.matched_value)
    return tuple(products)


def _build_finding(
    *,
    vendor_name: str,
    products: tuple[str, ...],
    behaviors: tuple[str, ...],
    evidence: list[AntiBotEvidence],
    anti_bot_aliases: AntiBotAliasCatalog | None = None,
) -> AntiBotFinding:
    score = _score_evidence(evidence)
    return AntiBotFinding(
        vendor=_canonical_vendor_name(vendor_name, anti_bot_aliases),
        score=score,
        confidence=_confidence_label(
            score,
            _vendor_confidence_thresholds(vendor_name, anti_bot_aliases),
        ),
        products=products or _extract_products(evidence),
        behaviors=behaviors,
        evidence=tuple(evidence),
    )


def _confidence_label(score: int, thresholds: _ConfidenceThresholds) -> str:
    if score >= thresholds.high:
        return "high"
    if score >= thresholds.medium:
        return "medium"
    return "low"


def _vendor_confidence_thresholds(
    vendor_name: str,
    anti_bot_aliases: AntiBotAliasCatalog | None = None,
) -> _ConfidenceThresholds:
    canonical_vendor = _canonical_vendor_name(vendor_name, anti_bot_aliases)
    for rule in _load_vendor_rules():
        if _canonical_vendor_name(rule.name, anti_bot_aliases) == canonical_vendor:
            return rule.confidence_thresholds
    return _load_calibration_config().default_confidence_thresholds


def _canonical_vendor_name(
    vendor_name: str,
    anti_bot_aliases: AntiBotAliasCatalog | None,
) -> str:
    if anti_bot_aliases is None:
        return vendor_name
    return anti_bot_aliases.canonical_vendor_name(vendor_name)


@lru_cache
def _load_signal_payload() -> Mapping[str, object]:
    package = "wappalyzer_pure.data"
    try:
        payload = json.loads(
            resources.files(package)
            .joinpath("antibot/anti_bot_signals_data.json")
            .read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        raise DataLoadError(f"failed to decode anti-bot signal data: {exc}") from exc
    return _ensure_string_mapping(payload, label="anti-bot signal payload")


@lru_cache
def _load_calibration_config() -> _CalibrationConfig:
    payload = _load_signal_payload()
    return _CalibrationConfig(
        evidence_weights=_parse_evidence_weights(payload.get("weights")),
        default_confidence_thresholds=_parse_confidence_thresholds(
            payload.get("default_confidence_thresholds")
        ),
    )


@lru_cache
def _load_vendor_rules() -> tuple[_VendorRule, ...]:
    payload = _load_signal_payload()
    vendors_payload = payload.get("vendors")
    if not isinstance(vendors_payload, list):
        raise DataLoadError("anti-bot signal data is missing the vendors list")

    return tuple(_parse_vendor_rule(item) for item in vendors_payload)


def _parse_vendor_rule(payload: object) -> _VendorRule:
    mapping = _ensure_string_mapping(payload, label="anti-bot vendor entry")
    name = _require_non_empty_string(mapping.get("name"), field="name")
    min_score = _parse_min_score(mapping.get("min_score"))
    signals = _parse_signal_rule(mapping.get("signals"))
    behaviors_payload = mapping.get("behaviors", [])
    if not isinstance(behaviors_payload, list):
        raise DataLoadError(f"anti-bot behaviors must be a list for vendor {name!r}")
    return _VendorRule(
        name=name,
        min_score=min_score,
        signals=signals,
        confidence_thresholds=_parse_confidence_thresholds(
            mapping.get("confidence_thresholds")
        ),
        behaviors=tuple(
            _parse_behavior_rule(item, vendor=name) for item in behaviors_payload
        ),
    )


def _parse_behavior_rule(payload: object, *, vendor: str) -> _BehaviorRule:
    mapping = _ensure_string_mapping(
        payload,
        label=f"anti-bot behavior entry for vendor {vendor!r}",
    )
    name = _require_non_empty_string(mapping.get("name"), field="name")
    return _BehaviorRule(
        name=name,
        min_score=_parse_min_score(mapping.get("min_score")),
        signals=_parse_signal_rule(mapping.get("signals")),
    )


def _parse_signal_rule(payload: object) -> _SignalRule:
    mapping = _ensure_string_mapping(payload, label="anti-bot signals")
    return _SignalRule(
        technology_names=_parse_string_list(mapping.get("technology_names")),
        cookie_names=_parse_string_list(mapping.get("cookie_names")),
        cookie_prefixes=_parse_string_list(mapping.get("cookie_prefixes")),
        header_names=_parse_string_list(mapping.get("header_names")),
        header_value_contains=_parse_header_value_contains(
            mapping.get("header_value_contains")
        ),
        body_substrings=_parse_string_list(mapping.get("body_substrings")),
        script_source_substrings=_parse_string_list(
            mapping.get("script_source_substrings")
        ),
        iframe_source_substrings=_parse_string_list(
            mapping.get("iframe_source_substrings")
        ),
        resource_url_substrings=_parse_string_list(
            mapping.get("resource_url_substrings")
        ),
        script_content_substrings=_parse_string_list(
            mapping.get("script_content_substrings")
        ),
        runtime_markers=_parse_string_list(mapping.get("runtime_markers")),
    )


def _parse_string_list(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise DataLoadError(f"anti-bot signal lists must be arrays, got {value!r}")
    items: list[str] = []
    for item in value:
        items.append(_require_non_empty_string(item, field="signal"))
    return tuple(item.casefold() for item in items)


def _parse_header_value_contains(
    value: object,
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if value is None:
        return ()
    mapping = _ensure_string_mapping(value, label="anti-bot header_value_contains")
    pairs: list[tuple[str, tuple[str, ...]]] = []
    for header_name, items in mapping.items():
        header = _require_non_empty_string(header_name, field="header")
        substrings = _parse_string_list(items)
        pairs.append((header.casefold(), substrings))
    return tuple(pairs)


def _parse_min_score(value: object) -> int:
    if value is None:
        return 3
    if not isinstance(value, int) or value <= 0:
        raise DataLoadError(
            f"anti-bot min_score must be a positive integer, got {value!r}"
        )
    return value


def _parse_evidence_weights(value: object) -> Mapping[str, int]:
    if value is None:
        return dict(_DEFAULT_EVIDENCE_WEIGHTS)
    mapping = _ensure_string_mapping(value, label="anti-bot evidence weights")
    weights = dict(_DEFAULT_EVIDENCE_WEIGHTS)
    for key, item in mapping.items():
        if not isinstance(item, int) or item < 0:
            raise DataLoadError(
                f"anti-bot evidence weight must be a non-negative integer, got {item!r}"
            )
        weights[key] = item
    return weights


def _parse_confidence_thresholds(value: object) -> _ConfidenceThresholds:
    if value is None:
        return _ConfidenceThresholds()
    mapping = _ensure_string_mapping(value, label="anti-bot confidence thresholds")
    medium = mapping.get("medium", 3)
    high = mapping.get("high", 5)
    if not isinstance(medium, int) or medium < 0:
        raise DataLoadError(
            f"anti-bot confidence medium threshold must be a non-negative integer, got {medium!r}"
        )
    if not isinstance(high, int) or high < medium:
        raise DataLoadError(
            f"anti-bot confidence high threshold must be an integer greater than or equal to medium, got {high!r}"
        )
    return _ConfidenceThresholds(medium=medium, high=high)


def _require_non_empty_string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise DataLoadError(
            f"anti-bot {field} must be a non-empty string, got {value!r}"
        )
    return value


def _ensure_string_mapping(
    value: object,
    *,
    label: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise DataLoadError(f"{label} must be a mapping, got {value!r}")
    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise DataLoadError(f"{label} keys must be strings, got {key!r}")
        result[key] = item
    return result
