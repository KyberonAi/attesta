"""Audit trail exporters for CSV and JSON formats.

Provides :class:`CSVExporter` and :class:`JSONExporter` that implement the
:class:`AuditExporter` protocol for exporting audit entries to standard
formats.

Usage::

    from attesta.core.audit import AuditLogger
    from attesta.exporters import CSVExporter

    audit = AuditLogger(path=".attesta/audit.jsonl")
    entries = audit.query(verdict="approved")

    with open("report.csv", "w") as f:
        CSVExporter().export(entries, f)
"""

from __future__ import annotations

import csv
import json
from typing import IO, Any, Protocol, runtime_checkable

from attesta.core.audit import AuditEntry

__all__ = ["AuditExporter", "CSVExporter", "JSONExporter"]

# Default columns for CSV export.
DEFAULT_COLUMNS: list[str] = [
    "entry_id",
    "intercepted_at",
    "action_name",
    "risk_score",
    "risk_level",
    "challenge_type",
    "verdict",
    "agent_id",
    "review_duration_seconds",
    "chain_hash",
]


@runtime_checkable
class AuditExporter(Protocol):
    """Protocol for audit trail exporters."""

    def export(self, entries: list[AuditEntry], output: IO[str]) -> None:
        """Write *entries* to *output* in the exporter's format."""
        ...


class CSVExporter:
    """Export audit entries as CSV.

    Parameters
    ----------
    columns:
        List of field names to include as columns. Defaults to
        :data:`DEFAULT_COLUMNS`. Nested dict fields (like ``metadata``)
        are JSON-serialised.
    """

    def __init__(self, columns: list[str] | None = None) -> None:
        self.columns = columns or list(DEFAULT_COLUMNS)

    def export(self, entries: list[AuditEntry], output: IO[str]) -> None:
        """Write *entries* to *output* as CSV."""
        writer = csv.writer(output)
        writer.writerow(self.columns)

        for entry in entries:
            row_dict = entry.to_dict()
            row: list[str] = []
            for col in self.columns:
                val = row_dict.get(col, "")
                # JSON-serialise complex types (dicts, lists)
                if isinstance(val, (dict, list)):
                    val = json.dumps(val, separators=(",", ":"))
                row.append(str(val) if val is not None else "")
            writer.writerow(row)


class JSONExporter:
    """Export audit entries as a JSON array.

    Parameters
    ----------
    indent:
        Number of spaces for pretty-printing. ``None`` for compact output.
    """

    def __init__(self, indent: int | None = 2) -> None:
        self.indent = indent

    def export(self, entries: list[AuditEntry], output: IO[str]) -> None:
        """Write *entries* to *output* as a JSON array."""
        data = [entry.to_dict() for entry in entries]
        json.dump(data, output, indent=self.indent, default=str)
        output.write("\n")
