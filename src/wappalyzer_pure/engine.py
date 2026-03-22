from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import lru_cache
from html.parser import HTMLParser
from importlib import resources
from typing import Any

from .data_sources import (
    DEFAULT_FINGERPRINT_DATA_SOURCE,
    FingerprintDataSource,
    categories_filename,
    fingerprints_filename,
    normalize_fingerprint_data_source,
)
from .exceptions import DataLoadError
from .patterns import ParsedPattern, parse_pattern


@dataclass(frozen=True, slots=True)
class CategoryInfo:
    name: str
    priority: int


@dataclass(frozen=True, slots=True)
class AppInfo:
    description: str | None
    website: str | None
    cpe: str | None
    icon: str | None
    categories: tuple[str, ...]


@dataclass(slots=True)
class CompiledFingerprint:
    cats: tuple[int, ...] = ()
    implies: tuple[str, ...] = ()
    description: str | None = None
    website: str | None = None
    cpe: str | None = None
    icon: str | None = None
    cookies: dict[str, ParsedPattern] = field(default_factory=dict)
    headers: dict[str, ParsedPattern] = field(default_factory=dict)
    html: tuple[ParsedPattern, ...] = ()
    script_src: tuple[ParsedPattern, ...] = ()
    scripts: tuple[ParsedPattern, ...] = ()
    meta: dict[str, tuple[ParsedPattern, ...]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MatchPartResult:
    application: str
    confidence: int
    version: str = ""


@dataclass(frozen=True, slots=True)
class HTMLArtifacts:
    script_sources: tuple[str, ...] = ()
    inline_scripts: tuple[str, ...] = ()
    metas: tuple[tuple[str, str], ...] = ()


@dataclass(slots=True)
class _UniqueFingerprintMetadata:
    confidence: int
    version: str = ""


class _Part(Enum):
    COOKIES = auto()
    HEADERS = auto()
    HTML = auto()
    SCRIPT_SRC = auto()
    SCRIPTS = auto()
    META = auto()


class UniqueFingerprints:
    def __init__(self) -> None:
        self._values: dict[str, _UniqueFingerprintMetadata] = {}

    def set_if_not_exists(self, value: str, version: str, confidence: int) -> None:
        existing = self._values.get(value)
        if existing is not None:
            updated_confidence = min(existing.confidence + confidence, 100)
            updated_version = existing.version or version
            self._values[value] = _UniqueFingerprintMetadata(
                confidence=updated_confidence,
                version=updated_version,
            )
            return

        self._values[value] = _UniqueFingerprintMetadata(
            confidence=confidence,
            version=version,
        )

    def get_values(self) -> dict[str, None]:
        values: dict[str, None] = {}
        for name, metadata in self._values.items():
            if metadata.confidence == 0:
                continue
            values[format_app_version(name, metadata.version)] = None
        return values


class Wappalyzer:
    def __init__(
        self,
        fingerprints: dict[str, Any],
        categories: dict[int, CategoryInfo],
    ) -> None:
        self.categories = categories
        self.apps: dict[str, CompiledFingerprint] = {
            name: compile_fingerprint(payload) for name, payload in fingerprints.items()
        }

    @classmethod
    def from_json_strings(
        cls,
        fingerprints_json: str,
        categories_json: str,
    ) -> Wappalyzer:
        try:
            fingerprints_payload = json.loads(fingerprints_json)
            categories_payload = json.loads(categories_json)
        except json.JSONDecodeError as exc:
            raise DataLoadError(f"failed to decode fingerprint data: {exc}") from exc

        apps = fingerprints_payload.get("apps")
        if not isinstance(apps, dict):
            raise DataLoadError("fingerprints JSON is missing the apps mapping")
        categories = _load_categories(categories_payload)
        return cls(apps, categories)

    @classmethod
    def from_package_data(
        cls,
        *,
        source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
    ) -> Wappalyzer:
        normalized_source = normalize_fingerprint_data_source(source)
        package = "wappalyzer_pure.data"
        fingerprints_json = (
            resources.files(package)
            .joinpath(fingerprints_filename(normalized_source))
            .read_text(encoding="utf-8")
        )
        categories_json = (
            resources.files(package)
            .joinpath(categories_filename(normalized_source))
            .read_text(encoding="utf-8")
        )
        return cls.from_json_strings(fingerprints_json, categories_json)

    def fingerprint(
        self,
        headers: dict[str, list[str]],
        body: bytes,
        *,
        html_artifacts: HTMLArtifacts | None = None,
        extra_script_contents: tuple[str, ...] = (),
    ) -> dict[str, None]:
        unique_fingerprints = UniqueFingerprints()
        normalized_headers = self.normalize_headers(headers)

        for app in self.check_headers(normalized_headers):
            unique_fingerprints.set_if_not_exists(
                app.application,
                app.version,
                app.confidence,
            )

        cookies = self.find_set_cookie(normalized_headers)
        if cookies:
            for app in self.check_cookies(cookies):
                unique_fingerprints.set_if_not_exists(
                    app.application,
                    app.version,
                    app.confidence,
                )

        for app in self.check_body(
            body,
            html_artifacts=html_artifacts,
            extra_script_contents=extra_script_contents,
        ):
            unique_fingerprints.set_if_not_exists(
                app.application,
                app.version,
                app.confidence,
            )

        return unique_fingerprints.get_values()

    def fingerprint_with_title(
        self,
        headers: dict[str, list[str]],
        body: bytes,
        *,
        html_artifacts: HTMLArtifacts | None = None,
        extra_script_contents: tuple[str, ...] = (),
    ) -> tuple[dict[str, None], str]:
        unique_fingerprints = UniqueFingerprints()
        normalized_headers = self.normalize_headers(headers)

        for app in self.check_headers(normalized_headers):
            unique_fingerprints.set_if_not_exists(
                app.application,
                app.version,
                app.confidence,
            )

        cookies = self.find_set_cookie(normalized_headers)
        if cookies:
            for app in self.check_cookies(cookies):
                unique_fingerprints.set_if_not_exists(
                    app.application,
                    app.version,
                    app.confidence,
                )

        if "text/html" in normalized_headers.get("content-type", ""):
            for app in self.check_body(
                body,
                html_artifacts=html_artifacts,
                extra_script_contents=extra_script_contents,
            ):
                unique_fingerprints.set_if_not_exists(
                    app.application,
                    app.version,
                    app.confidence,
                )
            return unique_fingerprints.get_values(), self.get_title(body)

        return unique_fingerprints.get_values(), ""

    def fingerprint_with_info(
        self,
        headers: dict[str, list[str]],
        body: bytes,
        *,
        html_artifacts: HTMLArtifacts | None = None,
        extra_script_contents: tuple[str, ...] = (),
    ) -> dict[str, AppInfo]:
        apps = self.fingerprint(
            headers,
            body,
            html_artifacts=html_artifacts,
            extra_script_contents=extra_script_contents,
        )
        result: dict[str, AppInfo] = {}

        for app in apps:
            fingerprint = self.apps.get(app)
            if fingerprint is None and ":" in app:
                parts = app.split(":")
                if len(parts) == 2:
                    fingerprint = self.apps.get(parts[0])
            if fingerprint is None:
                continue
            result[app] = app_info_from_fingerprint(fingerprint, self.categories)

        return result

    def check_headers(self, headers: dict[str, str]) -> list[MatchPartResult]:
        return self._match_map_string(headers, _Part.HEADERS)

    def check_cookies(self, cookies: list[str]) -> list[MatchPartResult]:
        normalized = self.normalize_cookies(cookies)
        return self._match_map_string(normalized, _Part.COOKIES)

    def check_body(
        self,
        body: bytes,
        *,
        html_artifacts: HTMLArtifacts | None = None,
        extra_script_contents: tuple[str, ...] = (),
    ) -> list[MatchPartResult]:
        technologies: list[MatchPartResult] = []
        body_text = body.decode("latin-1")
        normalized_body_text = body_text.lower()

        technologies.extend(self._match_string(normalized_body_text, _Part.HTML))

        parsed_artifacts = html_artifacts or extract_html_artifacts(body_text)

        for source in parsed_artifacts.script_sources:
            technologies.extend(self._match_string(source.lower(), _Part.SCRIPT_SRC))

        for script in parsed_artifacts.inline_scripts:
            technologies.extend(self._match_string(script.lower(), _Part.SCRIPTS))

        for script in extra_script_contents:
            technologies.extend(self._match_string(script.lower(), _Part.SCRIPTS))

        for name, content in parsed_artifacts.metas:
            technologies.extend(
                self._match_key_value_string(name.lower(), content.lower(), _Part.META)
            )

        return technologies

    def get_title(self, body: bytes) -> str:
        parser = _TitleHTMLParser()
        parser.feed(body.decode("latin-1"))
        parser.close()
        return parser.title

    def normalize_headers(self, headers: dict[str, list[str]]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for header, value in get_headers_map(headers).items():
            normalized[header.lower()] = value.lower()
        return normalized

    def normalize_cookies(self, cookies: list[str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for part in cookies:
            pieces = part.strip().split("=", 1)
            if len(pieces) < 2:
                continue
            normalized[pieces[0]] = pieces[1]
        return normalized

    def find_set_cookie(self, headers: dict[str, str]) -> list[str]:
        value = headers.get("set-cookie")
        if value is None:
            return []

        values: list[str] = []
        for token in value.split(" "):
            if not token:
                continue
            if "," in token:
                values.extend(token.split(","))
            elif ";" in token:
                values.extend(token.split(";"))
            else:
                values.append(token)
        return values

    def _match_string(self, data: str, part: _Part) -> list[MatchPartResult]:
        technologies: list[MatchPartResult] = []
        for app, fingerprint in self.apps.items():
            version = ""
            confidence = 100
            matched = False

            patterns = ()
            if part is _Part.HTML:
                patterns = fingerprint.html
            elif part is _Part.SCRIPT_SRC:
                patterns = fingerprint.script_src
            elif part is _Part.SCRIPTS:
                patterns = fingerprint.scripts

            for pattern in patterns:
                valid, version_string = pattern.evaluate(data)
                if not valid:
                    continue
                matched = True
                if not version and version_string:
                    version = version_string
                confidence = pattern.confidence

            if not matched:
                continue

            technologies.append(
                MatchPartResult(
                    application=app,
                    version=version,
                    confidence=confidence,
                )
            )
            for implied in fingerprint.implies:
                technologies.append(
                    MatchPartResult(application=implied, confidence=confidence)
                )

        return technologies

    def _match_key_value_string(
        self,
        key: str,
        value: str,
        part: _Part,
    ) -> list[MatchPartResult]:
        technologies: list[MatchPartResult] = []
        for app, fingerprint in self.apps.items():
            version = ""
            confidence = 100
            matched = False

            if part is _Part.COOKIES:
                pattern = fingerprint.cookies.get(key)
                if pattern is not None:
                    valid, version_string = pattern.evaluate(value)
                    if valid:
                        matched = True
                        if not version and version_string:
                            version = version_string
                        confidence = pattern.confidence
            elif part is _Part.HEADERS:
                pattern = fingerprint.headers.get(key)
                if pattern is not None:
                    valid, version_string = pattern.evaluate(value)
                    if valid:
                        matched = True
                        if not version and version_string:
                            version = version_string
                        confidence = pattern.confidence
            elif part is _Part.META:
                patterns = fingerprint.meta.get(key, ())
                for pattern in patterns:
                    valid, version_string = pattern.evaluate(value)
                    if not valid:
                        continue
                    matched = True
                    if not version and version_string:
                        version = version_string
                    confidence = pattern.confidence
                    break

            if not matched:
                continue

            technologies.append(
                MatchPartResult(
                    application=app,
                    version=version,
                    confidence=confidence,
                )
            )
            for implied in fingerprint.implies:
                technologies.append(
                    MatchPartResult(application=implied, confidence=confidence)
                )

        return technologies

    def _match_map_string(
        self,
        key_value: dict[str, str],
        part: _Part,
    ) -> list[MatchPartResult]:
        technologies: list[MatchPartResult] = []
        for app, fingerprint in self.apps.items():
            version = ""
            confidence = 100
            matched = False

            if part is _Part.META:
                for data, patterns in fingerprint.meta.items():
                    value = key_value.get(data)
                    if value is None:
                        continue
                    for pattern in patterns:
                        valid, version_string = pattern.evaluate(value)
                        if not valid:
                            continue
                        matched = True
                        if not version and version_string:
                            version = version_string
                        confidence = pattern.confidence
                        break
                    if matched:
                        break
            else:
                items = (
                    fingerprint.cookies.items()
                    if part is _Part.COOKIES
                    else fingerprint.headers.items()
                )
                for data, pattern in items:
                    value = key_value.get(data)
                    if value is None:
                        continue

                    valid, version_string = pattern.evaluate(value)
                    if not valid:
                        continue
                    matched = True
                    if not version and version_string:
                        version = version_string
                    confidence = pattern.confidence
                    break

            if not matched:
                continue

            technologies.append(
                MatchPartResult(
                    application=app,
                    version=version,
                    confidence=confidence,
                )
            )
            for implied in fingerprint.implies:
                technologies.append(
                    MatchPartResult(application=implied, confidence=confidence)
                )

        return technologies


class _FingerprintHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.script_sources: list[str] = []
        self.inline_scripts: list[str] = []
        self.metas: list[tuple[str, str]] = []
        self._in_script = False
        self._script_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_tag(tag, attrs, self_closing=False)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_tag(tag, attrs, self_closing=True)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._flush_script()

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_chunks.append(data)

    def _handle_tag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
        *,
        self_closing: bool,
    ) -> None:
        attributes = {name: value or "" for name, value in attrs}
        if tag == "script":
            if self._in_script:
                self._flush_script()
            source = attributes.get("src")
            if source:
                self.script_sources.append(source)
            self._in_script = not self_closing
            self._script_chunks = []
            return

        if tag == "meta":
            name = attributes.get("name", "")
            content = attributes.get("content", "")
            if name and content:
                self.metas.append((name, content))

    def _flush_script(self) -> None:
        if not self._in_script:
            self._script_chunks = []
            return

        script_text = "".join(self._script_chunks)
        if script_text.strip():
            self.inline_scripts.append(script_text)
        self._in_script = False
        self._script_chunks = []


class _TitleHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._in_title = False
        self.title = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and not self.title:
            self.title = data


def app_info_from_fingerprint(
    fingerprint: CompiledFingerprint,
    categories_mapping: dict[int, CategoryInfo],
) -> AppInfo:
    categories = tuple(
        category.name
        for cat in fingerprint.cats
        if (category := categories_mapping.get(cat)) is not None
    )
    return AppInfo(
        description=fingerprint.description,
        website=fingerprint.website,
        cpe=fingerprint.cpe,
        icon=fingerprint.icon,
        categories=categories,
    )


def extract_html_artifacts(body_text: str) -> HTMLArtifacts:
    parser = _FingerprintHTMLParser()
    parser.feed(body_text)
    parser.close()
    parser._flush_script()
    return HTMLArtifacts(
        script_sources=tuple(parser.script_sources),
        inline_scripts=tuple(parser.inline_scripts),
        metas=tuple(parser.metas),
    )


def compile_fingerprint(payload: dict[str, Any]) -> CompiledFingerprint:
    html_patterns: list[ParsedPattern] = []
    script_src_patterns: list[ParsedPattern] = []
    script_patterns: list[ParsedPattern] = []
    header_patterns: dict[str, ParsedPattern] = {}
    cookie_patterns: dict[str, ParsedPattern] = {}
    meta_patterns: dict[str, tuple[ParsedPattern, ...]] = {}

    for header, pattern in payload.get("headers", {}).items():
        parsed = _try_parse_pattern(pattern)
        if parsed is not None:
            header_patterns[str(header).lower()] = parsed

    for cookie, pattern in payload.get("cookies", {}).items():
        parsed = _try_parse_pattern(pattern)
        if parsed is not None:
            cookie_patterns[str(cookie).lower()] = parsed

    for pattern in payload.get("html", []):
        parsed = _try_parse_pattern(pattern)
        if parsed is not None:
            html_patterns.append(parsed)

    for pattern in payload.get("scriptSrc", []):
        parsed = _try_parse_pattern(pattern)
        if parsed is not None:
            script_src_patterns.append(parsed)

    for pattern in payload.get("scripts", []):
        parsed = _try_parse_pattern(pattern)
        if parsed is not None:
            script_patterns.append(parsed)

    for meta_name, patterns in payload.get("meta", {}).items():
        compiled_patterns = tuple(
            parsed
            for pattern in patterns
            if (parsed := _try_parse_pattern(pattern)) is not None
        )
        if compiled_patterns:
            meta_patterns[str(meta_name).lower()] = compiled_patterns

    return CompiledFingerprint(
        cats=tuple(int(cat) for cat in payload.get("cats", [])),
        implies=tuple(str(value) for value in payload.get("implies", [])),
        description=_optional_text(payload.get("description")),
        website=_optional_text(payload.get("website")),
        cpe=_optional_text(payload.get("cpe")),
        icon=_optional_text(payload.get("icon")),
        cookies=cookie_patterns,
        headers=header_patterns,
        html=tuple(html_patterns),
        script_src=tuple(script_src_patterns),
        scripts=tuple(script_patterns),
        meta=meta_patterns,
    )


def format_app_version(app: str, version: str) -> str:
    if not version:
        return app
    return f"{app}:{version}"


def get_headers_map(headers: dict[str, list[str]]) -> dict[str, str]:
    joined_headers: dict[str, str] = {}
    for key, values in headers.items():
        joined_headers[key] = ", ".join(values)
    return joined_headers


def _optional_text(value: object) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _try_parse_pattern(value: object) -> ParsedPattern | None:
    if not isinstance(value, str):
        return None
    try:
        return parse_pattern(value)
    except Exception:
        return None


def _load_categories(payload: dict[str, Any]) -> dict[int, CategoryInfo]:
    categories: dict[int, CategoryInfo] = {}
    for category, data in payload.items():
        if not isinstance(data, dict):
            continue
        name = data.get("name")
        priority = data.get("priority")
        if not isinstance(name, str) or not isinstance(priority, int):
            continue
        categories[int(category)] = CategoryInfo(name=name, priority=priority)
    return categories


def get_default_wappalyzer(
    source: FingerprintDataSource | str = DEFAULT_FINGERPRINT_DATA_SOURCE,
) -> Wappalyzer:
    normalized_source = normalize_fingerprint_data_source(source)
    return _get_default_wappalyzer_cached(normalized_source.value)


@lru_cache(maxsize=len(FingerprintDataSource))
def _get_default_wappalyzer_cached(source: str) -> Wappalyzer:
    return Wappalyzer.from_package_data(source=source)
