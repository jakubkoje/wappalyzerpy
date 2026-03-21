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
class AnalysisResult:
    target_url: str | None = None
    final_url: str | None = None
    status_code: int | None = None
    technologies: tuple[Technology, ...] = ()
    security_headers: tuple[SecurityHeaderStatus, ...] = ()
    body_length: int = 0

    @property
    def security_technologies(self) -> tuple[Technology, ...]:
        return tuple(
            technology
            for technology in self.technologies
            if technology.security_relevant
        )

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
            "security_headers": [header.to_dict() for header in self.security_headers],
        }
