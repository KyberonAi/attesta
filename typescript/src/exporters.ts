/**
 * Audit trail exporters for CSV and JSON formats.
 *
 * @example
 * ```ts
 * import { AuditLogger } from "@kyberon/attesta";
 * import { CSVExporter } from "@kyberon/attesta/exporters";
 *
 * const audit = new AuditLogger(".attesta/audit.jsonl");
 * const entries = audit.query({ verdict: "approved" });
 * const csv = new CSVExporter().export(entries);
 * ```
 */

import type { AuditEntryData } from "./audit.js";

// ---------------------------------------------------------------------------
// AuditExporter interface
// ---------------------------------------------------------------------------

/**
 * Interface for audit trail exporters.
 */
export interface AuditExporter {
  /** Export entries and return as a string. */
  export(entries: AuditEntryData[]): string;
}

// ---------------------------------------------------------------------------
// Default columns
// ---------------------------------------------------------------------------

export const DEFAULT_COLUMNS: readonly string[] = [
  "entryId",
  "interceptedAt",
  "actionName",
  "riskScore",
  "riskLevel",
  "challengeType",
  "verdict",
  "agentId",
  "reviewDurationSeconds",
  "chainHash",
] as const;

// ---------------------------------------------------------------------------
// CSVExporter
// ---------------------------------------------------------------------------

/**
 * Export audit entries as CSV.
 */
export class CSVExporter implements AuditExporter {
  readonly columns: readonly string[];

  constructor(options?: { columns?: string[] }) {
    this.columns = options?.columns ?? DEFAULT_COLUMNS;
  }

  export(entries: AuditEntryData[]): string {
    const lines: string[] = [];

    // Header
    lines.push(this.columns.join(","));

    // Rows
    for (const entry of entries) {
      const record = entry as unknown as Record<string, unknown>;
      const row = this.columns.map((col) => {
        const val = record[col];
        if (val == null) return "";
        if (typeof val === "object") return csvEscape(JSON.stringify(val));
        return csvEscape(String(val));
      });
      lines.push(row.join(","));
    }

    return lines.join("\n") + "\n";
  }
}

// ---------------------------------------------------------------------------
// JSONExporter
// ---------------------------------------------------------------------------

/**
 * Export audit entries as a JSON array.
 */
export class JSONExporter implements AuditExporter {
  readonly indent: number | undefined;

  constructor(options?: { indent?: number }) {
    this.indent = options?.indent ?? 2;
  }

  export(entries: AuditEntryData[]): string {
    return JSON.stringify(entries, null, this.indent) + "\n";
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function csvEscape(value: string): string {
  if (
    value.includes(",") ||
    value.includes('"') ||
    value.includes("\n")
  ) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}
