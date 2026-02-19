"""Tests for attesta.events -- EventBus, Event, EventType."""

from __future__ import annotations

import asyncio

import pytest

from attesta.events import Event, EventBus, EventType


class _SlowRenderer:
    async def render_approval(self, ctx, risk):
        await asyncio.sleep(9999)
        return None  # pragma: no cover

    async def render_challenge(self, ctx, risk, challenge_type):
        await asyncio.sleep(9999)
        return None  # pragma: no cover

    async def render_info(self, message):
        return None

    async def render_auto_approved(self, ctx, risk):
        return None


class TestEventType:
    def test_all_values(self):
        assert EventType.RISK_SCORED.value == "risk_scored"
        assert EventType.TRUST_COMPUTED.value == "trust_computed"
        assert EventType.CHALLENGE_ISSUED.value == "challenge_issued"
        assert EventType.CHALLENGE_COMPLETED.value == "challenge_completed"
        assert EventType.APPROVED.value == "approved"
        assert EventType.DENIED.value == "denied"
        assert EventType.ESCALATED.value == "escalated"
        assert EventType.AUDIT_LOGGED.value == "audit_logged"

    def test_member_count(self):
        assert len(EventType) == 8


class TestEvent:
    def test_defaults(self):
        e = Event(type=EventType.APPROVED)
        assert e.type is EventType.APPROVED
        assert isinstance(e.timestamp, float)
        assert e.data == {}

    def test_with_data(self):
        e = Event(type=EventType.RISK_SCORED, data={"score": 0.7})
        assert e.data["score"] == 0.7


class TestEventBus:
    def test_on_and_emit(self):
        bus = EventBus()
        received = []

        bus.on(EventType.APPROVED, lambda e: received.append(e))
        bus.emit(Event(type=EventType.APPROVED, data={"action": "deploy"}))

        assert len(received) == 1
        assert received[0].data["action"] == "deploy"

    def test_decorator_style(self):
        bus = EventBus()
        received = []

        @bus.on(EventType.DENIED)
        def handler(event):
            received.append(event)

        bus.emit(Event(type=EventType.DENIED))
        assert len(received) == 1

    def test_multiple_handlers(self):
        bus = EventBus()
        count = [0, 0]

        bus.on(EventType.APPROVED, lambda e: count.__setitem__(0, count[0] + 1))
        bus.on(EventType.APPROVED, lambda e: count.__setitem__(1, count[1] + 1))
        bus.emit(Event(type=EventType.APPROVED))

        assert count == [1, 1]

    def test_different_event_types_isolated(self):
        bus = EventBus()
        approved = []
        denied = []

        bus.on(EventType.APPROVED, lambda e: approved.append(e))
        bus.on(EventType.DENIED, lambda e: denied.append(e))

        bus.emit(Event(type=EventType.APPROVED))
        assert len(approved) == 1
        assert len(denied) == 0

    def test_off(self):
        bus = EventBus()
        received = []
        handler = lambda e: received.append(e)

        bus.on(EventType.APPROVED, handler)
        bus.emit(Event(type=EventType.APPROVED))
        assert len(received) == 1

        bus.off(EventType.APPROVED, handler)
        bus.emit(Event(type=EventType.APPROVED))
        assert len(received) == 1  # no new event

    def test_clear(self):
        bus = EventBus()
        received = []

        bus.on(EventType.APPROVED, lambda e: received.append(e))
        bus.clear()
        bus.emit(Event(type=EventType.APPROVED))
        assert len(received) == 0

    def test_error_in_handler_does_not_propagate(self):
        bus = EventBus()
        received = []

        def bad_handler(event):
            raise ValueError("boom")

        bus.on(EventType.APPROVED, bad_handler)
        bus.on(EventType.APPROVED, lambda e: received.append(e))

        # Should not raise
        bus.emit(Event(type=EventType.APPROVED))
        # The second handler still ran
        assert len(received) == 1

    async def test_async_on_and_emit(self):
        bus = EventBus()
        received = []

        @bus.async_on(EventType.APPROVED)
        async def handler(event):
            received.append(event)

        await bus.async_emit(Event(type=EventType.APPROVED))
        assert len(received) == 1

    async def test_async_emit_runs_sync_and_async(self):
        bus = EventBus()
        sync_received = []
        async_received = []

        bus.on(EventType.APPROVED, lambda e: sync_received.append(e))

        @bus.async_on(EventType.APPROVED)
        async def handler(event):
            async_received.append(event)

        await bus.async_emit(Event(type=EventType.APPROVED))
        assert len(sync_received) == 1
        assert len(async_received) == 1

    async def test_async_error_does_not_propagate(self):
        bus = EventBus()
        received = []

        @bus.async_on(EventType.APPROVED)
        async def bad_handler(event):
            raise ValueError("async boom")

        @bus.async_on(EventType.APPROVED)
        async def good_handler(event):
            received.append(event)

        await bus.async_emit(Event(type=EventType.APPROVED))
        assert len(received) == 1


class TestEventBusIntegration:
    """Test that events are emitted from the gate pipeline."""

    async def test_evaluate_emits_events(self):
        from attesta.core.gate import Attesta
        from attesta.core.types import ActionContext, RiskLevel

        bus = EventBus()
        events = []

        for et in EventType:
            bus.on(et, lambda e, _events=events: _events.append(e))

        g = Attesta(
            risk_override=RiskLevel.MEDIUM,
            event_bus=bus,
        )
        ctx = ActionContext(function_name="test_action")
        await g.evaluate(ctx)

        event_types = [e.type for e in events]
        assert EventType.RISK_SCORED in event_types
        assert EventType.APPROVED in event_types or EventType.DENIED in event_types

    async def test_timeout_escalation_emits_escalated_event(self):
        from attesta.core.gate import Attesta
        from attesta.core.types import ActionContext, RiskLevel

        bus = EventBus()
        events = []
        bus.on(EventType.ESCALATED, lambda e: events.append(e))

        g = Attesta(
            renderer=_SlowRenderer(),
            risk_override=RiskLevel.MEDIUM,
            event_bus=bus,
            fail_mode="escalate",
            approval_timeout_seconds=0.05,
        )
        ctx = ActionContext(function_name="slow_action")
        await g.evaluate(ctx)

        assert len(events) == 1
        assert events[0].data["verdict"] == "escalated"
