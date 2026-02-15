/**
 * Pub/sub event system for the attesta approval pipeline.
 *
 * The EventBus allows external code to subscribe to lifecycle events
 * emitted during Attesta.evaluate(), such as risk scoring, challenge
 * presentation, approval decisions, and audit logging.
 *
 * @example
 * ```ts
 * import { EventBus, EventType } from "@attesta/core";
 *
 * const bus = new EventBus();
 * bus.on(EventType.APPROVED, (event) => {
 *   console.log("Action approved:", event.data);
 * });
 *
 * const g = new Attesta({ eventBus: bus, ... });
 * ```
 */

// ---------------------------------------------------------------------------
// EventType
// ---------------------------------------------------------------------------

/**
 * Lifecycle events emitted during the approval pipeline.
 */
export const EventType = {
  RISK_SCORED: "risk_scored",
  TRUST_COMPUTED: "trust_computed",
  CHALLENGE_ISSUED: "challenge_issued",
  CHALLENGE_COMPLETED: "challenge_completed",
  APPROVED: "approved",
  DENIED: "denied",
  AUDIT_LOGGED: "audit_logged",
} as const;

export type EventType = (typeof EventType)[keyof typeof EventType];

// ---------------------------------------------------------------------------
// Event
// ---------------------------------------------------------------------------

/**
 * A single lifecycle event emitted by the pipeline.
 */
export interface Event {
  /** The type of event. */
  type: EventType;

  /** Unix timestamp (ms) when the event was created. */
  timestamp: number;

  /** Event-specific payload. */
  data: Record<string, unknown>;
}

/**
 * Create an Event with sensible defaults.
 */
export function createEvent(
  type: EventType,
  data: Record<string, unknown> = {}
): Event {
  return { type, timestamp: Date.now(), data };
}

// ---------------------------------------------------------------------------
// Handler types
// ---------------------------------------------------------------------------

/** Synchronous event handler. */
export type EventHandler = (event: Event) => void;

/** Async event handler. */
export type AsyncEventHandler = (event: Event) => Promise<void>;

// ---------------------------------------------------------------------------
// EventBus
// ---------------------------------------------------------------------------

/**
 * Publish/subscribe event bus for pipeline lifecycle events.
 *
 * Errors in handlers are caught and logged -- they never break the pipeline.
 */
export class EventBus {
  private readonly _handlers = new Map<EventType, EventHandler[]>();
  private readonly _asyncHandlers = new Map<EventType, AsyncEventHandler[]>();

  /**
   * Subscribe a sync handler to an event type.
   */
  on(eventType: EventType, handler: EventHandler): void {
    const handlers = this._handlers.get(eventType) ?? [];
    handlers.push(handler);
    this._handlers.set(eventType, handlers);
  }

  /**
   * Subscribe an async handler to an event type.
   */
  asyncOn(eventType: EventType, handler: AsyncEventHandler): void {
    const handlers = this._asyncHandlers.get(eventType) ?? [];
    handlers.push(handler);
    this._asyncHandlers.set(eventType, handlers);
  }

  /**
   * Remove a handler from an event type.
   */
  off(eventType: EventType, handler: EventHandler | AsyncEventHandler): void {
    const syncHandlers = this._handlers.get(eventType);
    if (syncHandlers) {
      const idx = syncHandlers.indexOf(handler as EventHandler);
      if (idx !== -1) syncHandlers.splice(idx, 1);
    }
    const asyncHandlers = this._asyncHandlers.get(eventType);
    if (asyncHandlers) {
      const idx = asyncHandlers.indexOf(handler as AsyncEventHandler);
      if (idx !== -1) asyncHandlers.splice(idx, 1);
    }
  }

  /**
   * Emit an event to all registered sync handlers.
   */
  emit(event: Event): void {
    const handlers = this._handlers.get(event.type) ?? [];
    for (const handler of handlers) {
      try {
        handler(event);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(
          `[attesta] Error in event handler for ${event.type}:`,
          err
        );
      }
    }
  }

  /**
   * Emit an event to both sync and async handlers.
   */
  async asyncEmit(event: Event): Promise<void> {
    // Fire sync handlers first
    this.emit(event);

    // Fire async handlers
    const asyncHandlers = this._asyncHandlers.get(event.type) ?? [];
    for (const handler of asyncHandlers) {
      try {
        await handler(event);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(
          `[attesta] Error in async event handler for ${event.type}:`,
          err
        );
      }
    }
  }

  /**
   * Remove all handlers for all event types.
   */
  clear(): void {
    this._handlers.clear();
    this._asyncHandlers.clear();
  }
}
