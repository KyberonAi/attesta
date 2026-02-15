"""Tests for the Attesta Approval Langflow component.

These tests mock the Langflow base classes and verify the component logic
independently of the Langflow runtime.
"""

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


class TestAttestaGate:
    """Tests for the AttestaGate component."""

    @patch("attesta_gate.Attesta")
    @pytest.mark.asyncio
    async def test_evaluate_gate_approved(
        self, mock_attesta_cls: MagicMock, approved_result: ApprovalResult
    ) -> None:
        mock_attesta = MagicMock()
        mock_attesta.evaluate = AsyncMock(return_value=approved_result)
        mock_attesta_cls.return_value = mock_attesta

        from attesta_gate import AttestaGate

        component = AttestaGate()
        component.function_name = "send_email"
        component.risk_level = "auto"
        component.action_args = '{"to": "user@example.com"}'
        component.risk_hints = "{}"
        component.log = MagicMock()

        result = await component.evaluate_gate()

        assert result.data["verdict"] == "approved"
        assert result.data["risk_score"] == 0.2
        assert result.data["risk_level"] == "low"
        assert result.data["denied"] is False
        assert result.data["audit_entry_id"] == "audit-123"

    @patch("attesta_gate.Attesta")
    @pytest.mark.asyncio
    async def test_evaluate_gate_denied(
        self, mock_attesta_cls: MagicMock, denied_result: ApprovalResult
    ) -> None:
        mock_attesta = MagicMock()
        mock_attesta.evaluate = AsyncMock(return_value=denied_result)
        mock_attesta_cls.return_value = mock_attesta

        from attesta_gate import AttestaGate

        component = AttestaGate()
        component.function_name = "delete_all_users"
        component.risk_level = "critical"
        component.action_args = "{}"
        component.risk_hints = '{"destructive": true}'
        component.log = MagicMock()

        result = await component.evaluate_gate()

        assert result.data["verdict"] == "denied"
        assert result.data["risk_score"] == 0.85
        assert result.data["denied"] is True

    @patch("attesta_gate.Attesta")
    @pytest.mark.asyncio
    async def test_risk_override(
        self, mock_attesta_cls: MagicMock, approved_result: ApprovalResult
    ) -> None:
        mock_attesta = MagicMock()
        mock_attesta.evaluate = AsyncMock(return_value=approved_result)
        mock_attesta_cls.return_value = mock_attesta

        from attesta_gate import AttestaGate

        component = AttestaGate()
        component.function_name = "test_action"
        component.risk_level = "high"
        component.action_args = "{}"
        component.risk_hints = "{}"
        component.log = MagicMock()

        await component.evaluate_gate()

        mock_attesta_cls.assert_called_once()
        call_kwargs = mock_attesta_cls.call_args[1]
        assert call_kwargs["risk_override"] == RiskLevel.HIGH

    @patch("attesta_gate.Attesta")
    @pytest.mark.asyncio
    async def test_auto_risk_level(
        self, mock_attesta_cls: MagicMock, approved_result: ApprovalResult
    ) -> None:
        mock_attesta = MagicMock()
        mock_attesta.evaluate = AsyncMock(return_value=approved_result)
        mock_attesta_cls.return_value = mock_attesta

        from attesta_gate import AttestaGate

        component = AttestaGate()
        component.function_name = "test_action"
        component.risk_level = "auto"
        component.action_args = "{}"
        component.risk_hints = "{}"
        component.log = MagicMock()

        await component.evaluate_gate()

        call_kwargs = mock_attesta_cls.call_args[1]
        assert call_kwargs["risk_override"] is None

    @patch("attesta_gate.Attesta")
    @pytest.mark.asyncio
    async def test_invalid_json_defaults_to_empty(
        self, mock_attesta_cls: MagicMock, approved_result: ApprovalResult
    ) -> None:
        mock_attesta = MagicMock()
        mock_attesta.evaluate = AsyncMock(return_value=approved_result)
        mock_attesta_cls.return_value = mock_attesta

        from attesta_gate import AttestaGate

        component = AttestaGate()
        component.function_name = "test_action"
        component.risk_level = "auto"
        component.action_args = "not valid json{{"
        component.risk_hints = "also invalid"
        component.log = MagicMock()

        result = await component.evaluate_gate()

        # Should still work — invalid JSON defaults to {}
        assert result.data["verdict"] == "approved"
