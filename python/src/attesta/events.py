"""Pub/sub event system for the attesta approval pipeline.

The :class:`EventBus` allows external code to subscribe to lifecycle events
emitted during :meth:`Attesta.evaluate`, such as risk scoring, challenge
presentation, approval decisions, and audit logging.

Usage::

    from attesta.events import EventBus, EventType

    bus = EventBus()

    @bus.on(EventType.APPROVED)
    def on_approved(event):
        print(f"Action approved: {event.data}")

    attesta = Attesta(event_bus=bus, ...)
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = ["EventType", "Event", "EventBus"]

logger = logging.getLogger("attesta.events")


class EventType(Enum):
    """Lifecycle events emitted during the approval pipeline."""

    RISK_SCORED = "risk_scored"
    TRUST_COMPUTED = "trust_computed"
    CHALLENGE_ISSUED = "challenge_issued"
    CHALLENGE_COMPLETED = "challenge_completed"
    APPROVED = "approved"
    DENIED = "denied"
    ESCALATED = "escalated"
    AUDIT_LOGGED = "audit_logged"


@dataclass
class Event:
    """A single lifecycle event emitted by the pipeline."""

    type: EventType
    timestamp: float = field(default_factory=time.time)
    data: dict[str, Any] = field(default_factory=dict)


# Type alias for event handler callbacks.
EventHandler = Callable[[Event], Any]


class EventBus:
    """Publish/subscribe event bus for pipeline lifecycle events.

    Thread-safe. Supports both sync and async handlers.

    Errors in handlers are caught and logged -- they never break the
    pipeline.
    """

    def __init__(self) -> None:
        self._handlers: dict[EventType, list[EventHandler]] = {}
        self._async_handlers: dict[EventType, list[Callable[[Event], Any]]] = {}
        self._lock = threading.Lock()

    def on(
        self, event_type: EventType, callback: EventHandler | None = None
    ) -> Callable:
        """Subscribe *callback* to *event_type*.

        Can be used as a decorator::

            @bus.on(EventType.APPROVED)
            def handler(event): ...

        Or called directly::

            bus.on(EventType.APPROVED, handler)
        """
        def decorator(fn: EventHandler) -> EventHandler:
            with self._lock:
                self._handlers.setdefault(event_type, []).append(fn)
            return fn

        if callback is not None:
            decorator(callback)
            return callback
        return decorator

    def async_on(
        self, event_type: EventType, callback: Callable[[Event], Any] | None = None
    ) -> Callable:
        """Subscribe an async callback to *event_type*.

        Usage::

            @bus.async_on(EventType.APPROVED)
            async def handler(event): ...
        """
        def decorator(fn: Callable[[Event], Any]) -> Callable[[Event], Any]:
            with self._lock:
                self._async_handlers.setdefault(event_type, []).append(fn)
            return fn

        if callback is not None:
            decorator(callback)
            return callback
        return decorator

    def off(self, event_type: EventType, callback: EventHandler) -> None:
        """Remove *callback* from *event_type* subscriptions."""
        with self._lock:
            handlers = self._handlers.get(event_type, [])
            try:
                handlers.remove(callback)
            except ValueError:
                pass
            async_handlers = self._async_handlers.get(event_type, [])
            try:
                async_handlers.remove(callback)
            except ValueError:
                pass

    def emit(self, event: Event) -> None:
        """Emit *event* to all registered sync handlers.

        Errors in handlers are caught and logged.
        """
        with self._lock:
            handlers = list(self._handlers.get(event.type, []))
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                logger.exception(
                    "Error in event handler %s for %s",
                    handler,
                    event.type.value,
                )

    async def async_emit(self, event: Event) -> None:
        """Emit *event* to both sync and async handlers.

        Sync handlers are called first, then async handlers are awaited.
        """
        # Fire sync handlers
        self.emit(event)

        # Fire async handlers
        with self._lock:
            async_handlers = list(self._async_handlers.get(event.type, []))
        for handler in async_handlers:
            try:
                await handler(event)
            except Exception:
                logger.exception(
                    "Error in async event handler %s for %s",
                    handler,
                    event.type.value,
                )

    def clear(self) -> None:
        """Remove all handlers for all event types."""
        with self._lock:
            self._handlers.clear()
            self._async_handlers.clear()
