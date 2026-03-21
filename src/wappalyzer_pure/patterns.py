from __future__ import annotations

import re
from dataclasses import dataclass

from .exceptions import PatternError

VER_CAP_1 = r"(\d+(?:\.\d+)+)"
VER_CAP_1_FILL = "__verCap1__"
VER_CAP_1_LIMITED = r"(\d{1,20}(?:\.\d{1,20}){1,20})"

VER_CAP_2 = r"((?:\d+\.)+\d+)"
VER_CAP_2_FILL = "__verCap2__"
VER_CAP_2_LIMITED = r"((?:\d{1,20}\.){1,20}\d{1,20})"


@dataclass(frozen=True, slots=True)
class ParsedPattern:
    regex: re.Pattern[str] | None
    confidence: int = 100
    version: str = ""
    skip_regex: bool = False

    def evaluate(self, target: str) -> tuple[bool, str]:
        if self.skip_regex:
            return True, ""
        if self.regex is None:
            return False, ""

        match = self.regex.search(target)
        if match is None:
            return False, ""

        try:
            version = self.extract_version(match.groups())
        except PatternError:
            version = ""
        return True, version

    def extract_version(self, submatches: tuple[str | None, ...]) -> str:
        result = self.version
        normalized_submatches = tuple(
            "" if value is None else value for value in submatches
        )
        for index, value in enumerate(normalized_submatches, start=1):
            result = result.replace(f"\\{index}", value)
        return evaluate_version_expression(result, normalized_submatches).strip()


def parse_pattern(pattern: str) -> ParsedPattern:
    parts = pattern.split(r"\;")
    confidence = 100
    version = ""
    skip_regex = parts[0] == ""
    compiled_regex: re.Pattern[str] | None = None

    for index, part in enumerate(parts):
        if index == 0:
            if skip_regex:
                continue

            regex_pattern = part
            regex_pattern = regex_pattern.replace(VER_CAP_1, VER_CAP_1_FILL)
            regex_pattern = regex_pattern.replace(VER_CAP_2, VER_CAP_2_FILL)
            regex_pattern = regex_pattern.replace(r"\+", "__escapedPlus__")
            regex_pattern = regex_pattern.replace("+", "{1,250}")
            regex_pattern = regex_pattern.replace("*", "{0,250}")
            regex_pattern = regex_pattern.replace("__escapedPlus__", r"\+")
            regex_pattern = regex_pattern.replace(VER_CAP_1_FILL, VER_CAP_1_LIMITED)
            regex_pattern = regex_pattern.replace(VER_CAP_2_FILL, VER_CAP_2_LIMITED)

            try:
                compiled_regex = re.compile(regex_pattern, re.IGNORECASE)
            except re.error as exc:
                raise PatternError(f"invalid regex pattern: {pattern}") from exc
            continue

        key, separator, value = part.partition(":")
        if not separator:
            continue
        if key == "confidence":
            try:
                confidence = int(value)
            except ValueError:
                confidence = 100
        elif key == "version":
            version = value

    return ParsedPattern(
        regex=compiled_regex,
        confidence=confidence,
        version=version,
        skip_regex=skip_regex,
    )


def evaluate_version_expression(
    expression: str,
    submatches: tuple[str, ...],
) -> str:
    if "?" not in expression:
        return expression

    parts = expression.split("?")
    if len(parts) != 2:
        raise PatternError(f"invalid ternary expression: {expression}")

    true_false_parts = parts[1].split(":")
    if len(true_false_parts) != 2:
        raise PatternError(
            f"invalid true/false parts in ternary expression: {expression}"
        )

    if true_false_parts[0] != "":
        if len(submatches) == 0:
            return true_false_parts[1]
        return true_false_parts[0]

    if true_false_parts[1] == "":
        if len(submatches) == 0:
            return ""
        return true_false_parts[0]

    return true_false_parts[1]
