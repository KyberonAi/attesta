"""Tests for the Attesta Approval Dify tool."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from attesta.core.types import (
    ApprovalResult,
    RiskAssessment,
    RiskLevel,
    Verdict,
)


@pytest.fixture
def approved_result() -> ApprovalResult:
    return ApprovalResult(
        verdict=Verdict.APPROVED,
        risk_assessment=RiskAssessment(
            score=0.2,
            level=RiskLevel.LOW,
            scorer_name="default",
        ),
        audit_entry_id="audit-123",
        review_time_seconds=0.5,
    )


@pytest.fixture
def denied_result() -> ApprovalResult:
    return ApprovalResult(
        verdict=Verdict.DENIED,
        risk_assessment=RiskAssessment(
            score=0.85,
            level=RiskLevel.CRITICAL,
            scorer_name="default",
        ),
        audit_entry_id="audit-456",
        review_time_seconds=1.0,
    )


class TestAttestaProvider:
    """Tests for the Attesta provider."""

    @patch("provider.attesta.ToolProvider", MagicMock)
    def test_validate_credentials_valid(self) -> None:
        from provider.attesta import AttestaProvider

        provider = AttestaProvider.__new__(AttestaProvider)
        # Should not raise
        provider._validate_credentials({"risk_threshold": 0.5})
        provider._validate_credentials({"risk_threshold": 0.0})
        provider._validate_credentials({"risk_threshold": 1.0})
        provider._validate_credentials({})

    @patch("provider.attesta.ToolProvider", MagicMock)
    def test_validate_credentials_invalid(self) -> None:
        from provider.attesta import AttestaProvider

        provider = AttestaProvider.__new__(AttestaProvider)
        with pytest.raises(Exception):
            provider._validate_credentials({"risk_threshold": 1.5})
        with pytest.raises(Exception):
            provider._validate_credentials({"risk_threshold": -0.1})


class TestAttestaGateTool:
    """Tests for the Attesta Approval tool."""

    @patch("tools.attesta_gate.Attesta")
    def test_invoke_approved(
        self, mock_attesta_cls: MagicMock, approved_result: ApprovalResult
    ) -> None:
        mock_attesta = MagicMock()
        mock_attesta.evaluate = AsyncMock(return_value=approved_result)
        mock_attesta_cls.return_value = mock_attesta

        from tools.attesta_gate import AttestaGateTool

        tool = AttestaGateTool.__new__(AttestaGateTool)
        tool.runtime = MagicMock()
        tool.runtime.credentials = {}

        messages = list(tool._invoke({
            "function_name": "send_email",
            "risk_level": "auto",
            "action_args": '{"to": "user@example.com"}',
        }))

        assert len(messages) == 1
        # The message should contain approved verdict info

    @patch("tools.attesta_gate.Attesta")
    def test_invoke_denied(
        self, mock_attesta_cls: MagicMock, denied_result: ApprovalResult
    ) -> None:
        mock_attesta = MagicMock()
        mock_attesta.evaluate = AsyncMock(return_value=denied_result)
        mock_attesta_cls.return_value = mock_attesta

        from tools.attesta_gate import AttestaGateTool

        tool = AttestaGateTool.__new__(AttestaGateTool)
        tool.runtime = MagicMock()
        tool.runtime.credentials = {}

        messages = list(tool._invoke({
            "function_name": "delete_all",
            "risk_level": "critical",
            "action_args": "{}",
        }))

        assert len(messages) == 1

    @patch("tools.attesta_gate.Attesta")
    def test_invoke_with_risk_override(
        self, mock_attesta_cls: MagicMock, approved_result: ApprovalResult
    ) -> None:
        mock_attesta = MagicMock()
        mock_attesta.evaluate = AsyncMock(return_value=approved_result)
        mock_attesta_cls.return_value = mock_attesta

        from tools.attesta_gate import AttestaGateTool

        tool = AttestaGateTool.__new__(AttestaGateTool)
        tool.runtime = MagicMock()
        tool.runtime.credentials = {"risk_threshold": "0.3"}

        list(tool._invoke({
            "function_name": "test_action",
            "risk_level": "high",
            "action_args": "{}",
        }))

        mock_attesta_cls.assert_called_once()
        call_kwargs = mock_attesta_cls.call_args[1]
        assert call_kwargs["risk_override"] == RiskLevel.HIGH
