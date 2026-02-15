"""Webhook notifications for attesta pipeline events.

Built on top of the :mod:`attesta.events` system, :class:`WebhookDispatcher`
subscribes to configured event types and sends HTTP POST requests with
JSON payloads to external endpoints.

Usage::

    from attesta.events import EventBus, EventType
    from attesta.webhooks import WebhookConfig, WebhookDispatcher

    bus = EventBus()
    config = WebhookConfig(
        url="https://hooks.example.com/attesta",
        events=[EventType.APPROVED, EventType.DENIED],
        secret="my-shared-secret",
    )
    dispatcher = WebhookDispatcher(bus, [config])

Zero external dependencies -- uses :mod:`urllib.request` from stdlib.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from attesta.events import Event, EventBus, EventType

__all__ = ["WebhookConfig", "WebhookDispatcher"]

logger = logging.getLogger("attesta.webhooks")


@dataclass
class WebhookConfig:
    """Configuration for a single webhook endpoint.

    Parameters
    ----------
    url:
        HTTP(S) endpoint to POST events to.
    events:
        List of event types to send. An empty list means *all* events.
    secret:
        Optional shared secret for HMAC-SHA256 signature verification.
        When set, an ``X-Attesta-Signature`` header is included.
    timeout:
        HTTP request timeout in seconds.
    retry_count:
        Number of retries on failure (0 = no retries).
    """

    url: str
    events: list[EventType] = field(default_factory=list)
    secret: str | None = None
    timeout: float = 5.0
    retry_count: int = 1


class WebhookDispatcher:
    """Subscribes to an EventBus and dispatches HTTP webhooks.

    Webhook deliveries happen in background threads (fire-and-forget)
    so they never block the approval pipeline.

    Parameters
    ----------
    event_bus:
        The :class:`EventBus` to subscribe to.
    configs:
        List of :class:`WebhookConfig` defining where to send events.
    """

    def __init__(
        self, event_bus: EventBus, configs: list[WebhookConfig]
    ) -> None:
        self._configs = configs
        self._event_bus = event_bus

        # Subscribe to all relevant event types.
        subscribed: set[EventType] = set()
        for config in configs:
            types = config.events or list(EventType)
            for event_type in types:
                if event_type not in subscribed:
                    event_bus.on(event_type, self._handle_event)
                    subscribed.add(event_type)

    def _handle_event(self, event: Event) -> None:
        """Route an event to the appropriate webhook configs."""
        for config in self._configs:
            if config.events and event.type not in config.events:
                continue
            # Fire in a background thread to avoid blocking the pipeline.
            thread = threading.Thread(
                target=self._send,
                args=(config, event),
                daemon=True,
            )
            thread.start()

    def _send(self, config: WebhookConfig, event: Event) -> None:
        """Send the webhook HTTP request (with retries)."""
        payload = self._build_payload(event)
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        headers: dict[str, str] = {
            "Content-Type": "application/json",
        }
        if config.secret:
            sig = hmac.new(
                config.secret.encode("utf-8"),
                body,
                hashlib.sha256,
            ).hexdigest()
            headers["X-Attesta-Signature"] = f"sha256={sig}"

        attempts = 1 + config.retry_count
        for attempt in range(attempts):
            try:
                req = Request(
                    config.url,
                    data=body,
                    headers=headers,
                    method="POST",
                )
                with urlopen(req, timeout=config.timeout) as resp:
                    status = resp.status
                    if 200 <= status < 300:
                        logger.debug(
                            "Webhook delivered to %s (status=%d)",
                            config.url,
                            status,
                        )
                        return
                    logger.warning(
                        "Webhook to %s returned status %d (attempt %d/%d)",
                        config.url,
                        status,
                        attempt + 1,
                        attempts,
                    )
            except (URLError, OSError, TimeoutError) as exc:
                logger.warning(
                    "Webhook to %s failed (attempt %d/%d): %s",
                    config.url,
                    attempt + 1,
                    attempts,
                    exc,
                )

            # Brief delay before retry.
            if attempt < attempts - 1:
                time.sleep(0.5)

        logger.error(
            "Webhook to %s exhausted all %d attempts",
            config.url,
            attempts,
        )

    @staticmethod
    def _build_payload(event: Event) -> dict[str, Any]:
        """Build the JSON payload for a webhook delivery."""
        return {
            "event": event.type.value.upper(),
            "timestamp": datetime.fromtimestamp(
                event.timestamp, tz=timezone.utc
            ).isoformat(),
            "data": event.data,
        }
