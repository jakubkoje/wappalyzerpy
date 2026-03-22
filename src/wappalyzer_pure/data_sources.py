from __future__ import annotations

from enum import Enum


class FingerprintDataSource(str, Enum):
    MERGED = "merged"
    ENTHEC = "enthec"
    HTTPARCHIVE = "httparchive"


DEFAULT_FINGERPRINT_DATA_SOURCE = FingerprintDataSource.MERGED


def normalize_fingerprint_data_source(
    value: FingerprintDataSource | str,
) -> FingerprintDataSource:
    if isinstance(value, FingerprintDataSource):
        return value
    return FingerprintDataSource(str(value).lower())


def fingerprints_filename(source: FingerprintDataSource | str) -> str:
    normalized = normalize_fingerprint_data_source(source)
    return f"fingerprints_{normalized.value}_data.json"


def categories_filename(source: FingerprintDataSource | str) -> str:
    normalized = normalize_fingerprint_data_source(source)
    return f"categories_{normalized.value}_data.json"
