#!/usr/bin/env python3
"""Lightweight benchmark harness for Python gate evaluation latency."""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from pathlib import Path

import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON_SRC = REPO_ROOT / "python" / "src"
if str(PYTHON_SRC) not in sys.path:
    sys.path.insert(0, str(PYTHON_SRC))

from attesta.core.gate import Attesta  # noqa: E402
from attesta.core.types import (  # noqa: E402
    ActionContext,
    ChallengeResult,
    ChallengeType,
    RiskAssessment,
    RiskLevel,
    Verdict,
)


class FastApproveRenderer:
    async def render_approval(
        self,
        _ctx: ActionContext,
        _risk: RiskAssessment,
    ) -> Verdict:
        return Verdict.APPROVED

    async def render_challenge(
        self,
        _ctx: ActionContext,
        _risk: RiskAssessment,
        challenge_type: ChallengeType,
    ) -> ChallengeResult:
        return ChallengeResult(
            passed=True,
            challenge_type=challenge_type,
            responder="bench",
        )

    async def render_info(self, _message: str) -> None:
        return None

    async def render_auto_approved(
        self,
        _ctx: ActionContext,
        _risk: RiskAssessment,
    ) -> None:
        return None


class SilentAuditLogger:
    async def log(self, _ctx: ActionContext, _result: object) -> str:
        return "bench"


def _summarize(samples_ms: list[float]) -> dict[str, float]:
    if not samples_ms:
        return {"p50_ms": 0.0, "p95_ms": 0.0, "mean_ms": 0.0}
    sorted_samples = sorted(samples_ms)
    p50_idx = int(0.50 * (len(sorted_samples) - 1))
    p95_idx = int(0.95 * (len(sorted_samples) - 1))
    return {
        "p50_ms": round(sorted_samples[p50_idx], 6),
        "p95_ms": round(sorted_samples[p95_idx], 6),
        "mean_ms": round(statistics.fmean(sorted_samples), 6),
    }


async def _measure_case(
    gate: Attesta,
    ctx: ActionContext,
    *,
    iterations: int,
    warmup: int,
) -> dict[str, float]:
    for _ in range(warmup):
        await gate.evaluate(ctx)

    samples_ms: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        await gate.evaluate(ctx)
        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
        samples_ms.append(elapsed_ms)
    return _summarize(samples_ms)


async def _run(iterations: int, warmup: int) -> dict[str, object]:
    renderer = FastApproveRenderer()
    audit_logger = SilentAuditLogger()

    low_gate = Attesta(
        renderer=renderer,
        audit_logger=audit_logger,
        risk_override=RiskLevel.LOW,
    )
    low_ctx = ActionContext(function_name="list_users")

    high_gate = Attesta(
        renderer=renderer,
        audit_logger=audit_logger,
        risk_override=RiskLevel.HIGH,
    )
    high_ctx = ActionContext(
        function_name="delete_production_records",
        kwargs={"table": "users"},
        hints={"destructive": True, "pii": True},
        environment="production",
    )

    low_result = await _measure_case(
        low_gate,
        low_ctx,
        iterations=iterations,
        warmup=warmup,
    )
    high_result = await _measure_case(
        high_gate,
        high_ctx,
        iterations=iterations,
        warmup=warmup,
    )

    return {
        "benchmark": "attesta-python",
        "iterations": iterations,
        "warmup": warmup,
        "cases": {
            "low_risk_auto_approve": low_result,
            "high_risk_challenge_pass": high_result,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--warmup", type=int, default=50)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    report = asyncio.run(_run(args.iterations, args.warmup))
    report_json = json.dumps(report, indent=2)

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report_json + "\n", encoding="utf-8")
        print(f"Wrote benchmark report: {args.output}")
    else:
        print(report_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
