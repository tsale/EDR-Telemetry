from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .config import StatsConfig
from .scoring import STATUS_SCORE


METADATA_KEYS = {"Telemetry Feature Category", "Sub-Category"}
STATUS_CANONICAL = {status.lower(): status for status in STATUS_SCORE}


@dataclass
class MatrixCell:
    platform: str
    file_path: str
    telemetry_feature_category: str
    sub_category: str
    vendor_name: str
    vendor_canonical_id: str
    vendor_display_name: str
    status: str
    row_index: int


@dataclass
class MatrixSnapshot:
    platform: str
    file_path: str
    cells: dict[tuple[str, str, str], MatrixCell] = field(default_factory=dict)
    warnings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def vendors(self) -> set[str]:
        return {key[2] for key in self.cells}

    @property
    def feature_keys(self) -> set[tuple[str, str]]:
        return {(key[0], key[1]) for key in self.cells}


def parse_matrix_content(
    content: str | None,
    *,
    platform: str,
    file_path: str,
    config: StatsConfig,
    strict: bool = False,
) -> MatrixSnapshot:
    snapshot = MatrixSnapshot(platform=platform, file_path=file_path)
    if content is None:
        return snapshot

    try:
        rows = json.loads(content)
    except json.JSONDecodeError as exc:
        warning = {
            "kind": "failed_json_parse",
            "platform": platform,
            "file_path": file_path,
            "message": str(exc),
        }
        if strict:
            raise ValueError(warning["message"]) from exc
        snapshot.warnings.append(warning)
        return snapshot

    if not isinstance(rows, list):
        warning = {
            "kind": "invalid_matrix_shape",
            "platform": platform,
            "file_path": file_path,
            "message": "Telemetry matrix JSON must be a list of row objects.",
        }
        if strict:
            raise ValueError(warning["message"])
        snapshot.warnings.append(warning)
        return snapshot

    current_category: str | None = None
    for row_index, row in enumerate(rows):
        if not isinstance(row, dict):
            snapshot.warnings.append(
                {
                    "kind": "invalid_matrix_row",
                    "platform": platform,
                    "file_path": file_path,
                    "row_index": row_index,
                    "message": "Matrix row is not an object.",
                }
            )
            continue

        raw_category = row.get("Telemetry Feature Category")
        if raw_category not in (None, ""):
            current_category = str(raw_category).strip()
        sub_category = str(row.get("Sub-Category") or "").strip()
        if not current_category or not sub_category:
            snapshot.warnings.append(
                {
                    "kind": "missing_row_identity",
                    "platform": platform,
                    "file_path": file_path,
                    "row_index": row_index,
                    "message": "Row is missing Telemetry Feature Category or Sub-Category.",
                }
            )
            continue

        for key, raw_status in row.items():
            if key in METADATA_KEYS:
                continue
            vendor_name = str(key).strip()
            status = normalize_status(raw_status)
            if status not in STATUS_SCORE:
                warning = {
                    "kind": "unknown_status",
                    "platform": platform,
                    "file_path": file_path,
                    "row_index": row_index,
                    "vendor": vendor_name,
                    "status": status,
                    "message": f"Unknown telemetry status {status!r}; score defaults to 0.",
                }
                if strict:
                    raise ValueError(warning["message"])
                snapshot.warnings.append(warning)

            canonical_id, display_name = config.canonicalize_vendor(vendor_name)
            cell_key = (current_category, sub_category, canonical_id)
            if cell_key in snapshot.cells:
                snapshot.warnings.append(
                    {
                        "kind": "duplicate_vendor_cell",
                        "platform": platform,
                        "file_path": file_path,
                        "row_index": row_index,
                        "vendor": vendor_name,
                        "vendor_canonical_id": canonical_id,
                        "message": "Multiple columns map to the same canonical vendor and feature.",
                    }
                )
            snapshot.cells[cell_key] = MatrixCell(
                platform=platform,
                file_path=file_path,
                telemetry_feature_category=current_category,
                sub_category=sub_category,
                vendor_name=vendor_name,
                vendor_canonical_id=canonical_id,
                vendor_display_name=display_name,
                status=status,
                row_index=row_index,
            )

    return snapshot


def normalize_status(value: Any) -> str:
    status = "" if value is None else str(value).strip()
    return STATUS_CANONICAL.get(status.lower(), status)
