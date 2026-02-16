/**
 * Browser-based challenge renderer using a local HTTP server.
 *
 * Zero external dependencies -- uses the built-in `http` module.
 *
 * The WebRenderer starts a lightweight HTTP server, serves HTML pages
 * for each challenge type, and waits for the operator's response.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";

import {
  type ActionContext,
  type ChallengeResult,
  ChallengeType,
  type Renderer,
  type RiskAssessment,
  Verdict,
  createChallengeResult,
  describeAction,
} from "../types.js";

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ---------------------------------------------------------------------------
// CSS
// ---------------------------------------------------------------------------

const CSS = `
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  max-width: 700px; margin: 40px auto; padding: 0 20px;
  background: #f8faf8; color: #1a1a1a;
}
h1 { color: #2d7a3a; border-bottom: 2px solid #2d7a3a; padding-bottom: 8px; }
.risk-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; color: white; font-size: 14px; }
.risk-low { background: #2d7a3a; }
.risk-medium { background: #d4a017; }
.risk-high { background: #d45317; }
.risk-critical { background: #c0392b; }
.detail { margin: 12px 0; padding: 12px; background: white; border-radius: 6px; border: 1px solid #e0e0e0; }
.detail label { font-weight: bold; color: #555; }
textarea { width: 100%; min-height: 120px; font-size: 15px; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
.btn { padding: 10px 28px; font-size: 16px; border: none; border-radius: 6px; cursor: pointer; margin-right: 10px; color: white; }
.btn-approve { background: #2d7a3a; }
.btn-approve:disabled { background: #a0c4a7; cursor: not-allowed; }
.btn-deny { background: #c0392b; }
.countdown { color: #888; font-size: 13px; margin-top: 8px; }
`;

function riskBadge(level: string): string {
  const cls =
    level === "low"
      ? "risk-low"
      : level === "high"
        ? "risk-high"
        : level === "critical"
          ? "risk-critical"
          : "risk-medium";
  return `<span class="risk-badge ${cls}">${escapeHtml(level.toUpperCase())}</span>`;
}

function baseHtml(
  title: string,
  body: string,
  minReviewSeconds: number = 0
): string {
  let countdownJs = "";
  if (minReviewSeconds > 0) {
    countdownJs = `
<script>
(function() {
  var remaining = ${Math.ceil(minReviewSeconds)};
  var btn = document.getElementById('submit-btn');
  var countdown = document.getElementById('countdown');
  if (btn) btn.disabled = true;
  var iv = setInterval(function() {
    remaining--;
    if (countdown) countdown.textContent = 'Submit available in ' + remaining + 's...';
    if (remaining <= 0) {
      clearInterval(iv);
      if (btn) btn.disabled = false;
      if (countdown) countdown.textContent = '';
    }
  }, 1000);
})();
</script>`;
  }
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${title}</title><style>${CSS}</style></head><body>${body}${countdownJs}</body></html>`;
}

function confirmPage(ctx: ActionContext, risk: RiskAssessment): string {
  return baseHtml(
    "Attesta - Confirm",
    `<h1>Attesta -- Approval Required</h1>
<div class="detail">
  <label>Action:</label> ${escapeHtml(ctx.functionName)}<br>
  <label>Call:</label> ${escapeHtml(describeAction(ctx))}<br>
  <label>Risk:</label> ${riskBadge(risk.level)} (${risk.score.toFixed(2)})
</div>
<form method="POST" action="/respond">
  <button class="btn btn-approve" type="submit" name="verdict" value="approve" id="submit-btn">Approve</button>
  <button class="btn btn-deny" type="submit" name="verdict" value="deny">Deny</button>
</form>
<div class="countdown" id="countdown"></div>`
  );
}

function teachBackPage(
  ctx: ActionContext,
  risk: RiskAssessment,
  minReview: number
): string {
  return baseHtml(
    "Attesta - Teach-Back",
    `<h1>Attesta -- Teach-Back Challenge</h1>
<div class="detail">
  <label>Action:</label> ${escapeHtml(ctx.functionName)}<br>
  <label>Call:</label> ${escapeHtml(describeAction(ctx))}<br>
  <label>Risk:</label> ${riskBadge(risk.level)} (${risk.score.toFixed(2)})
</div>
<form method="POST" action="/respond">
  <p><strong>In your own words, explain what this action will do and its effects:</strong></p>
  <textarea name="explanation" placeholder="Type your explanation here..." required></textarea><br><br>
  <button class="btn btn-approve" type="submit" id="submit-btn">Submit Explanation</button>
</form>
<div class="countdown" id="countdown"></div>`,
    minReview
  );
}

function resultPage(passed: boolean): string {
  const status = passed ? "APPROVED" : "DENIED";
  const color = passed ? "#2d7a3a" : "#c0392b";
  return baseHtml(
    `Attesta - ${status}`,
    `<h1 style="color: ${color}">Challenge Result: ${status}</h1>
<p>You may close this tab. The pipeline has been notified.</p>`
  );
}

// ---------------------------------------------------------------------------
// WebRendererOptions
// ---------------------------------------------------------------------------

export interface WebRendererOptions {
  /** Bind address. Default "127.0.0.1". */
  host?: string;

  /** TCP port. Default 8910. */
  port?: number;

  /** Whether to auto-open the browser. Default true. */
  autoOpen?: boolean;

  /** Minimum seconds before submit becomes active. Default 0. */
  minReviewSeconds?: number;
}

// ---------------------------------------------------------------------------
// WebRenderer
// ---------------------------------------------------------------------------

/**
 * Browser-based renderer using a local HTTP server.
 */
export class WebRenderer implements Renderer {
  readonly host: string;
  readonly port: number;
  readonly autoOpen: boolean;
  readonly minReviewSeconds: number;
  private _csrfToken: string = "";

  constructor(options: WebRendererOptions = {}) {
    this.host = options.host ?? "127.0.0.1";
    this.port = options.port ?? 8910;
    this.autoOpen = options.autoOpen ?? true;
    this.minReviewSeconds = options.minReviewSeconds ?? 0;
  }

  async renderApproval(
    ctx: ActionContext,
    risk: RiskAssessment
  ): Promise<Verdict> {
    const html = confirmPage(ctx, risk);
    const response = await this._serveAndWait(html);
    return response.get("verdict") === "approve"
      ? Verdict.APPROVED
      : Verdict.DENIED;
  }

  async renderChallenge(
    ctx: ActionContext,
    risk: RiskAssessment,
    challengeType: ChallengeType
  ): Promise<ChallengeResult> {
    const start = performance.now();

    if (challengeType === ChallengeType.MULTI_PARTY) {
      // Fail closed: WebRenderer is single-session and cannot enforce
      // independent multi-party approvals safely.
      return createChallengeResult({
        passed: false,
        challengeType,
        responseTimeSeconds: (performance.now() - start) / 1000,
        questionsAsked: 0,
        questionsCorrect: 0,
        details: {
          source: "web",
          reason:
            "multi-party challenge is unsupported by WebRenderer; configure a renderer that supports independent approvers",
        },
      });
    }

    let html: string;
    if (challengeType === ChallengeType.TEACH_BACK) {
      html = teachBackPage(ctx, risk, this.minReviewSeconds);
    } else {
      html = confirmPage(ctx, risk);
    }

    const response = await this._serveAndWait(html);
    const elapsed = (performance.now() - start) / 1000;

    let passed: boolean;
    if (challengeType === ChallengeType.TEACH_BACK) {
      const explanation = response.get("explanation") ?? "";
      passed = explanation.split(/\s+/).filter(Boolean).length >= 5;
    } else {
      passed = response.get("verdict") === "approve";
    }

    return createChallengeResult({
      passed,
      challengeType,
      responseTimeSeconds: elapsed,
      questionsAsked: 1,
      questionsCorrect: passed ? 1 : 0,
      details: { source: "web" },
    });
  }

  async renderInfo(_message: string): Promise<void> {
    // No-op for web renderer
  }

  async renderAutoApproved(
    _ctx: ActionContext,
    _risk: RiskAssessment
  ): Promise<void> {
    // No-op for web renderer
  }

  // -- internal ---------------------------------------------------------

  private _serveAndWait(html: string): Promise<Map<string, string>> {
    this._csrfToken = randomBytes(32).toString("hex");
    const csrfToken = this._csrfToken;

    // Inject CSRF token into forms
    html = html.replace(
      '<form method="POST" action="/respond">',
      `<form method="POST" action="/respond"><input type="hidden" name="_csrf" value="${csrfToken}">`
    );

    return new Promise((resolve) => {
      const result = new Map<string, string>();

      const server = createServer((req: IncomingMessage, res: ServerResponse) => {
        if (req.method === "GET") {
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(html);
          return;
        }

        if (req.method === "POST") {
          let body = "";
          let bodySize = 0;
          const MAX_BODY = 65536; // 64KB
          req.on("data", (chunk: Buffer) => {
            bodySize += chunk.length;
            if (bodySize <= MAX_BODY) {
              body += chunk.toString();
            }
          });
          req.on("end", () => {
            if (bodySize > MAX_BODY) {
              res.writeHead(413, { "Content-Type": "text/plain" });
              res.end("Request body too large");
              return;
            }

            // Parse form data
            const params = new URLSearchParams(body);

            // Validate CSRF token
            const submittedCsrf = params.get("_csrf") ?? "";
            if (submittedCsrf !== csrfToken) {
              res.writeHead(403, { "Content-Type": "text/plain" });
              res.end("CSRF token invalid");
              return;
            }

            for (const [k, v] of params) {
              result.set(k, v);
            }

            const passed =
              result.get("verdict") === "approve" ||
              !!result.get("explanation");
            const respHtml = resultPage(passed);
            res.writeHead(200, {
              "Content-Type": "text/html; charset=utf-8",
            });
            res.end(respHtml);

            // Shut down after response
            clearTimeout(timeout);
            server.close();
            resolve(result);
          });
        }
      });

      server.listen(this.port, this.host, () => {
        const url = `http://${this.host}:${this.port}`;
        // eslint-disable-next-line no-console
        console.log(`[attesta] Web challenge at ${url}`);

        if (this.autoOpen) {
          import("node:child_process")
            .then(({ execFile }) => {
              if (process.platform === "darwin") {
                execFile("open", [url]);
              } else if (process.platform === "win32") {
                execFile("cmd", ["/c", "start", url]);
              } else {
                execFile("xdg-open", [url]);
              }
            })
            .catch(() => {
              // Ignore browser open failures
            });
        }
      });

      const timeout = setTimeout(() => {
        server.close();
        resolve(result); // Empty result maps to denied
      }, 600_000); // 10 minute timeout
    });
  }
}
