/**
 * Webhook notifications for attesta pipeline events.
 *
 * Built on top of the events system, WebhookDispatcher subscribes to
 * configured event types and sends HTTP POST requests with JSON payloads
 * to external endpoints.
 *
 * Uses the global `fetch` API (available in Node.js 18+).
 */

import { createHmac } from "node:crypto";
import type { Event, EventBus, EventType } from "./events.js";

// ---------------------------------------------------------------------------
// WebhookConfig
// ---------------------------------------------------------------------------

/**
 * Configuration for a single webhook endpoint.
 */
export interface WebhookConfig {
  /** HTTP(S) endpoint to POST events to. */
  url: string;

  /** Event types to send. Empty array means all events. */
  events?: EventType[];

  /** Optional shared secret for HMAC-SHA256 signature. */
  secret?: string;

  /** HTTP request timeout in milliseconds. Default 5000. */
  timeoutMs?: number;

  /** Number of retries on failure (0 = no retries). Default 1. */
  retryCount?: number;
}

// ---------------------------------------------------------------------------
// WebhookDispatcher
// ---------------------------------------------------------------------------

/**
 * Subscribes to an EventBus and dispatches HTTP webhooks.
 *
 * Webhook deliveries are fire-and-forget (async, non-blocking).
 */
export class WebhookDispatcher {
  private readonly _configs: WebhookConfig[];

  constructor(eventBus: EventBus, configs: WebhookConfig[]) {
    this._configs = configs;

    // Subscribe to all relevant event types.
    const subscribed = new Set<string>();
    for (const config of configs) {
      const types = config.events ?? [];
      if (types.length === 0) {
        // Subscribe to all by using a catch-all
        if (!subscribed.has("*")) {
          // We need to import EventType values at subscription time
          const allTypes = [
            "risk_scored",
            "trust_computed",
            "challenge_issued",
            "challenge_completed",
            "approved",
            "denied",
            "audit_logged",
          ];
          for (const t of allTypes) {
            if (!subscribed.has(t)) {
              eventBus.on(
                t as EventType,
                (event: Event) => this._handleEvent(event)
              );
              subscribed.add(t);
            }
          }
          subscribed.add("*");
        }
      } else {
        for (const eventType of types) {
          if (!subscribed.has(eventType)) {
            eventBus.on(eventType, (event: Event) =>
              this._handleEvent(event)
            );
            subscribed.add(eventType);
          }
        }
      }
    }
  }

  private _handleEvent(event: Event): void {
    for (const config of this._configs) {
      if (
        config.events &&
        config.events.length > 0 &&
        !config.events.includes(event.type)
      ) {
        continue;
      }
      // Fire-and-forget
      this._send(config, event).catch((err) => {
        // eslint-disable-next-line no-console
        console.error(`[attesta] Webhook to ${config.url} failed:`, err);
      });
    }
  }

  private async _send(config: WebhookConfig, event: Event): Promise<void> {
    const payload = buildPayload(event);
    const body = JSON.stringify(payload);

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (config.secret) {
      const sig = createHmac("sha256", config.secret)
        .update(body)
        .digest("hex");
      headers["X-Attesta-Signature"] = `sha256=${sig}`;
    }

    const attempts = 1 + (config.retryCount ?? 1);
    const timeoutMs = config.timeoutMs ?? 5000;

    for (let attempt = 0; attempt < attempts; attempt++) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);

        const response = await fetch(config.url, {
          method: "POST",
          headers,
          body,
          signal: controller.signal,
        });

        clearTimeout(timer);

        if (response.ok) return;

        // eslint-disable-next-line no-console
        console.warn(
          `[attesta] Webhook to ${config.url} returned ${response.status} (attempt ${attempt + 1}/${attempts})`
        );
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(
          `[attesta] Webhook to ${config.url} failed (attempt ${attempt + 1}/${attempts}):`,
          err
        );
      }

      // Brief delay before retry
      if (attempt < attempts - 1) {
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildPayload(event: Event): Record<string, unknown> {
  return {
    event: event.type.toUpperCase(),
    timestamp: new Date(event.timestamp).toISOString(),
    data: event.data,
  };
}
