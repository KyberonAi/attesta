"""Tests for attesta.exporters -- CSVExporter, JSONExporter."""

from __future__ import annotations

import io
import json

import pytest

from attesta.core.audit import AuditEntry
from attesta.exporters import CSVExporter, JSONExporter, AuditExporter


def _make_entry(**kwargs) -> AuditEntry:
    """Create a test AuditEntry with overrides."""
    defaults = dict(
        entry_id="abc123",
        action_name="deploy_service",
        risk_score=0.75,
        risk_level="high",
        challenge_type="quiz",
        verdict="approved",
        agent_id="agent-007",
        review_duration_seconds=12.5,
        intercepted_at="2024-01-15T10:30:00",
        decided_at="2024-01-15T10:30:12",
        environment="production",
        chain_hash="a" * 64,
    )
    defaults.update(kwargs)
    return AuditEntry(**defaults)


class TestCSVExporter:
    def test_header_row(self):
        exporter = CSVExporter()
        buf = io.StringIO()
        exporter.export([], buf)
        output = buf.getvalue()
        assert "entry_id" in output
        assert "action_name" in output

    def test_single_entry(self):
        entry = _make_entry()
        exporter = CSVExporter()
        buf = io.StringIO()
        exporter.export([entry], buf)
        output = buf.getvalue()
        lines = output.strip().split("\n")
        assert len(lines) == 2
        assert "deploy_service" in lines[1]
        assert "0.75" in lines[1]

    def test_custom_columns(self):
        entry = _make_entry()
        exporter = CSVExporter(columns=["action_name", "verdict"])
        buf = io.StringIO()
        exporter.export([entry], buf)
        output = buf.getvalue()
        lines = [l.strip() for l in output.strip().split("\n")]
        assert lines[0] == "action_name,verdict"
        assert "deploy_service,approved" in lines[1]

    def test_metadata_serialized_as_json(self):
        entry = _make_entry(metadata={"team": "platform"})
        exporter = CSVExporter(columns=["action_name", "metadata"])
        buf = io.StringIO()
        exporter.export([entry], buf)
        output = buf.getvalue()
        assert "platform" in output

    def test_satisfies_protocol(self):
        assert isinstance(CSVExporter(), AuditExporter)


class TestJSONExporter:
    def test_empty_list(self):
        exporter = JSONExporter()
        buf = io.StringIO()
        exporter.export([], buf)
        data = json.loads(buf.getvalue())
        assert data == []

    def test_single_entry(self):
        entry = _make_entry()
        exporter = JSONExporter()
        buf = io.StringIO()
        exporter.export([entry], buf)
        data = json.loads(buf.getvalue())
        assert len(data) == 1
        assert data[0]["action_name"] == "deploy_service"
        assert data[0]["risk_score"] == 0.75

    def test_compact_output(self):
        exporter = JSONExporter(indent=None)
        buf = io.StringIO()
        exporter.export([_make_entry()], buf)
        # Compact output should be a single line (plus trailing newline)
        lines = buf.getvalue().strip().split("\n")
        assert len(lines) == 1

    def test_satisfies_protocol(self):
        assert isinstance(JSONExporter(), AuditExporter)


class TestAuditLoggerExport:
    def test_export_csv(self, tmp_path):
        from attesta.core.audit import AuditLogger

        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(path=log_path)
        entry = _make_entry()
        audit.log_entry(entry)

        buf = io.StringIO()
        audit.export(format="csv", output=buf)
        output = buf.getvalue()
        assert "entry_id" in output
        assert "deploy_service" in output

    def test_export_json(self, tmp_path):
        from attesta.core.audit import AuditLogger

        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(path=log_path)
        entry = _make_entry()
        audit.log_entry(entry)

        buf = io.StringIO()
        audit.export(format="json", output=buf)
        data = json.loads(buf.getvalue())
        assert len(data) == 1
        assert data[0]["action_name"] == "deploy_service"
