"""Tests for attesta.webhooks -- WebhookConfig, WebhookDispatcher."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from attesta.events import Event, EventBus, EventType
from attesta.webhooks import WebhookConfig, WebhookDispatcher


class _WebhookHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that records received webhooks."""

    received: list[dict] = []
    received_headers: list[dict] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        data = json.loads(body)
        _WebhookHandler.received.append(data)
        _WebhookHandler.received_headers.append(dict(self.headers))
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress logs during tests


@pytest.fixture()
def webhook_server():
    """Start a local HTTP server and yield its URL."""
    _WebhookHandler.received = []
    _WebhookHandler.received_headers = []
    server = HTTPServer(("127.0.0.1", 0), _WebhookHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


class TestWebhookPayload:
    def test_payload_structure(self):
        event = Event(
            type=EventType.APPROVED,
            data={"action_name": "deploy", "risk_score": 0.82},
        )
        payload = WebhookDispatcher._build_payload(event)
        assert payload["event"] == "APPROVED"
        assert "timestamp" in payload
        assert payload["data"]["action_name"] == "deploy"
        assert payload["data"]["risk_score"] == 0.82


class TestWebhookDispatcher:
    def test_sends_webhook(self, webhook_server):
        bus = EventBus()
        config = WebhookConfig(url=webhook_server, events=[EventType.APPROVED])
        WebhookDispatcher(bus, [config])

        bus.emit(Event(type=EventType.APPROVED, data={"action": "test"}))

        # Wait for background thread to complete
        time.sleep(1.0)

        assert len(_WebhookHandler.received) == 1
        assert _WebhookHandler.received[0]["event"] == "APPROVED"
        assert _WebhookHandler.received[0]["data"]["action"] == "test"

    def test_hmac_signature(self, webhook_server):
        bus = EventBus()
        secret = "test-secret-key"
        config = WebhookConfig(
            url=webhook_server,
            events=[EventType.DENIED],
            secret=secret,
        )
        WebhookDispatcher(bus, [config])

        bus.emit(Event(type=EventType.DENIED, data={"reason": "failed"}))
        time.sleep(1.0)

        assert len(_WebhookHandler.received) == 1
        sig_header = _WebhookHandler.received_headers[0].get("X-Attesta-Signature", "")
        assert sig_header.startswith("sha256=")

        # Verify the signature
        body = json.dumps(_WebhookHandler.received[0], separators=(",", ":")).encode("utf-8")
        expected_sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        assert sig_header == f"sha256={expected_sig}"

    def test_filters_by_event_type(self, webhook_server):
        bus = EventBus()
        config = WebhookConfig(url=webhook_server, events=[EventType.APPROVED])
        WebhookDispatcher(bus, [config])

        # Emit a DENIED event -- should NOT trigger webhook
        bus.emit(Event(type=EventType.DENIED, data={}))
        time.sleep(0.5)

        assert len(_WebhookHandler.received) == 0

    def test_all_events_when_empty(self, webhook_server):
        bus = EventBus()
        config = WebhookConfig(url=webhook_server, events=[])
        WebhookDispatcher(bus, [config])

        bus.emit(Event(type=EventType.RISK_SCORED, data={}))
        time.sleep(1.0)

        assert len(_WebhookHandler.received) == 1

    def test_timeout_does_not_block(self):
        bus = EventBus()
        config = WebhookConfig(
            url="http://192.0.2.1:1",  # RFC 5737 TEST-NET (will timeout)
            events=[EventType.APPROVED],
            timeout=0.1,
            retry_count=0,
        )
        WebhookDispatcher(bus, [config])

        start = time.monotonic()
        bus.emit(Event(type=EventType.APPROVED, data={}))
        elapsed = time.monotonic() - start

        # Should return almost immediately (fire-and-forget)
        assert elapsed < 0.5
