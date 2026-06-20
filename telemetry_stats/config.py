from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return slug or "unknown"


@dataclass
class VendorAlias:
    canonical_id: str
    display_name: str
    aliases: list[str] = field(default_factory=list)


@dataclass
class StatsConfig:
    maintainers: set[str] = field(default_factory=lambda: {"tsale"})
    bots: set[str] = field(default_factory=lambda: {"dependabot", "github-actions", "github-actions[bot]"})
    vendor_aliases: dict[str, VendorAlias] = field(default_factory=dict)
    vendor_affiliations: dict[str, set[str]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "StatsConfig":
        data = data or {}
        contributor_classes = data.get("contributor_classes") or {}
        maintainers = {str(login).lower() for login in (data.get("maintainers") or contributor_classes.get("maintainers") or ["tsale"])}
        bots = {str(login).lower() for login in (data.get("bots") or contributor_classes.get("bots") or ["dependabot", "github-actions", "github-actions[bot]"])}

        aliases: dict[str, VendorAlias] = {}
        for canonical_id, item in (data.get("vendor_aliases") or {}).items():
            if item is None:
                item = {}
            display_name = str(item.get("display_name") or canonical_id)
            alias_values = [str(alias) for alias in (item.get("aliases") or [])]
            if display_name not in alias_values:
                alias_values.append(display_name)
            aliases[str(canonical_id)] = VendorAlias(str(canonical_id), display_name, alias_values)

        affiliations: dict[str, set[str]] = {}
        for canonical_id, item in (data.get("vendor_affiliations") or {}).items():
            if isinstance(item, dict):
                logins = item.get("github_logins") or []
            else:
                logins = item or []
            affiliations[str(canonical_id)] = {str(login).lower() for login in logins}

        return cls(maintainers=maintainers, bots=bots, vendor_aliases=aliases, vendor_affiliations=affiliations)

    @classmethod
    def load(cls, path: str | Path | None) -> "StatsConfig":
        if not path:
            return cls()
        config_path = Path(path)
        if not config_path.exists():
            return cls()
        return cls.from_dict(_load_yaml(config_path))

    def canonicalize_vendor(self, vendor_name: str) -> tuple[str, str]:
        normalized = vendor_name.strip()
        lookup = normalized.lower()
        for canonical_id, alias in self.vendor_aliases.items():
            if lookup == alias.display_name.lower() or lookup in {value.lower() for value in alias.aliases}:
                return canonical_id, alias.display_name
        return slugify(normalized), normalized

    def contributor_class(self, login: str | None) -> str:
        if not login:
            return "unknown"
        lookup = login.lower()
        if lookup in self.maintainers:
            return "maintainer"
        if lookup in self.bots:
            return "bot"
        for logins in self.vendor_affiliations.values():
            if lookup in logins:
                return "vendor"
        return "external_contributor"

    def vendor_for_login(self, login: str | None) -> str | None:
        if not login:
            return None
        lookup = login.lower()
        for canonical_id, logins in self.vendor_affiliations.items():
            if lookup in logins:
                return canonical_id
        return None


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml

        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    except ImportError:
        return _minimal_yaml_load(path.read_text(encoding="utf-8"))


def _minimal_yaml_load(text: str) -> dict[str, Any]:
    """Small fallback parser for the simple config shape used by this project."""
    result: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, result)]
    last_key_at_indent: dict[int, str] = {}

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if line.startswith("- "):
            value = line[2:].strip().strip('"').strip("'")
            if isinstance(parent, list):
                parent.append(value)
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value:
            parsed: Any = value.strip('"').strip("'")
        else:
            parsed = {}
        if isinstance(parent, dict):
            parent[key] = parsed
            last_key_at_indent[indent] = key
            if parsed == {}:
                stack.append((indent, parsed))
        if key in {"maintainers", "bots", "aliases", "github_logins"} and parsed == {}:
            new_list: list[str] = []
            parent[key] = new_list
            stack[-1] = (indent, new_list)
    return result
