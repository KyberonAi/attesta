"""Rich terminal renderer for attesta.

Provides a beautiful, colourful terminal UI using the ``rich`` library.
Falls back to a plain-text ``PlainRenderer`` when ``rich`` is not installed
or the ``NO_COLOR`` environment variable is set.

Classes
-------
TerminalRenderer
    Full-featured renderer with rich panels, coloured risk bars, and
    interactive prompts.
PlainRenderer
    Simple ``print()`` / ``input()`` fallback for minimal environments.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time

from attesta.core.types import (
    ActionContext,
    ChallengeResult,
    ChallengeType,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
    Verdict,
)
from attesta.renderers.base import BaseRenderer

# ---------------------------------------------------------------------------
# Try importing rich -- graceful degradation if unavailable
# ---------------------------------------------------------------------------

_RICH_AVAILABLE = False

try:
    if not os.environ.get("NO_COLOR"):
        from rich.console import Console
        from rich.markup import escape as rich_escape
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
        from rich.align import Align

        _RICH_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_BAR_WIDTH = 10

_RISK_COLORS: dict[RiskLevel, str] = {
    RiskLevel.LOW: "green",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "red",
    RiskLevel.CRITICAL: "bright_red",
}

_RISK_ICONS: dict[RiskLevel, str] = {
    RiskLevel.LOW: "",
    RiskLevel.MEDIUM: "",
    RiskLevel.HIGH: "\U0001f512",       # lock
    RiskLevel.CRITICAL: "\u26d4",        # no entry
}

_MIN_REVIEW_SECONDS: dict[RiskLevel, float] = {
    RiskLevel.LOW: 0.0,
    RiskLevel.MEDIUM: 0.0,
    RiskLevel.HIGH: 5.0,
    RiskLevel.CRITICAL: 30.0,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _risk_bar_plain(score: float, width: int = _BAR_WIDTH) -> str:
    """Build a plain-text risk bar like ``████░░░░░░``."""
    filled = round(score * width)
    return "\u2588" * filled + "\u2591" * (width - filled)


def _format_call(ctx: ActionContext, max_len: int = 60) -> str:
    """Format the function call string, truncating if needed."""
    desc = ctx.description
    if len(desc) > max_len:
        desc = desc[: max_len - 3] + "..."
    return desc


async def _async_input(prompt: str = "") -> str:
    """Non-blocking ``input()`` that plays nicely with asyncio.

    Returns an empty string on ``EOFError`` or ``KeyboardInterrupt``
    so callers in non-interactive environments (Docker, CI, piped input)
    degrade gracefully instead of crashing.
    """
    loop = asyncio.get_running_loop()

    def _read() -> str:
        try:
            return input(prompt)
        except (EOFError, KeyboardInterrupt):
            return ""

    return await loop.run_in_executor(None, _read)


async def _countdown(seconds: float, label: str = "Minimum review") -> None:
    """Print a ticking countdown, overwriting the line in-place."""
    remaining = seconds
    while remaining > 0:
        sys.stdout.write(f"\r  \u23f1  {label}: {remaining:.0f}s remaining  ")
        sys.stdout.flush()
        tick = min(1.0, remaining)
        await asyncio.sleep(tick)
        remaining -= tick
    # Clear the countdown line
    sys.stdout.write("\r" + " " * 60 + "\r")
    sys.stdout.flush()


# ===================================================================
# PlainRenderer -- no-dependency fallback
# ===================================================================

class PlainRenderer(BaseRenderer):
    """Minimal renderer using only ``print()`` and ``input()``.

    Used automatically when ``rich`` is not installed or ``NO_COLOR``
    is set.  All output goes to stdout/stderr with no ANSI codes.
    """

    # ---- auto-approved (LOW) ------------------------------------------

    async def render_auto_approved(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> None:
        bar = _risk_bar_plain(risk.score)
        print(
            f"  \u2713 AUTO  {_format_call(ctx)}"
            f"  Risk: {bar} {risk.level.value.upper()} ({risk.score:.2f})"
        )

    # ---- approval prompt (MEDIUM) -------------------------------------

    async def render_approval(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> Verdict:
        sep = "=" * 56
        bar = _risk_bar_plain(risk.score)

        print()
        print(f"  {sep}")
        print(f"  ATTESTA")
        print(f"  {sep}")
        print(f"  Action: {ctx.function_name}")
        print(f"  Risk:   {bar} {risk.level.value.upper()} ({risk.score:.2f})")
        print(f"  Call:   {_format_call(ctx)}")
        if risk.factors:
            print()
            print(f"  Risk Factors:")
            for f in risk.factors:
                fbar = _risk_bar_plain(f.contribution)
                print(f"    {f.name:<20s} {fbar} {f.contribution:.2f}")
        print()
        print(f"  [a] Approve  [d] Deny  [e] Edit  [?] Explain")
        print(f"  {sep}")

        while True:
            response = (await _async_input("  > ")).strip().lower()
            if response in ("a", "approve", "y", "yes"):
                return Verdict.APPROVED
            if response in ("d", "deny", "n", "no"):
                return Verdict.DENIED
            if response in ("e", "edit"):
                return Verdict.MODIFIED
            if response == "?":
                self._print_explanation(ctx, risk)
                continue
            print("  Please enter [a]pprove, [d]eny, [e]dit, or [?] explain.")

    # ---- challenge (HIGH / CRITICAL) ----------------------------------

    async def render_challenge(
        self,
        ctx: ActionContext,
        risk: RiskAssessment,
        challenge_type: ChallengeType,
    ) -> ChallengeResult:
        if challenge_type == ChallengeType.TEACH_BACK:
            return await self._render_teach_back(ctx, risk)
        if challenge_type in (ChallengeType.QUIZ, ChallengeType.CONFIRM):
            return await self._render_quiz_challenge(ctx, risk)
        if challenge_type == ChallengeType.MULTI_PARTY:
            return await self._render_multi_party(ctx, risk)
        # Unknown challenge type -- fall back to quiz
        return await self._render_quiz_challenge(ctx, risk)

    async def _render_quiz_challenge(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> ChallengeResult:
        start = time.monotonic()
        sep = "=" * 56
        bar = _risk_bar_plain(risk.score)

        print()
        print(f"  {sep}")
        print(f"  ATTESTA -- {risk.level.value.upper()} RISK")
        print(f"  {sep}")
        print(f"  Action: {ctx.function_name}")
        print(f"  Risk:   {bar} {risk.level.value.upper()} ({risk.score:.2f})")
        print(f"  Call:   {_format_call(ctx)}")
        if risk.factors:
            print()
            print(f"  Risk Factors:")
            for f in risk.factors:
                fbar = _risk_bar_plain(f.contribution)
                print(f"    {f.name:<20s} {fbar} {f.contribution:.2f}")
        print(f"  {sep}")

        # Enforce minimum review
        min_review = _MIN_REVIEW_SECONDS.get(risk.level, 0.0)
        if min_review > 0:
            await _countdown(min_review)

        # Comprehension question
        question = self._generate_question(ctx, risk)
        print()
        print(f"  Comprehension Check:")
        print(f"  {question}")
        answer = await _async_input("  > ")

        elapsed = time.monotonic() - start
        passed = len(answer.strip()) > 0

        return ChallengeResult(
            passed=passed,
            challenge_type=ChallengeType.QUIZ,
            response_time_seconds=round(elapsed, 3),
            questions_asked=1,
            questions_correct=1 if passed else 0,
            details={"question": question, "answer": answer.strip()},
        )

    async def _render_teach_back(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> ChallengeResult:
        start = time.monotonic()
        sep = "=" * 56
        bar = _risk_bar_plain(risk.score)

        print()
        print(f"  {sep}")
        print(f"  ATTESTA -- CRITICAL")
        print(f"  {sep}")
        print(f"  Action: {ctx.function_name}")
        print(f"  Risk:   {bar} CRITICAL ({risk.score:.2f})")
        print(f"  Call:   {_format_call(ctx)}")
        print(f"  {sep}")

        # Enforce minimum review
        min_review = _MIN_REVIEW_SECONDS[RiskLevel.CRITICAL]
        await _countdown(min_review)

        print()
        print(f"  Explain what this action will do and its effects:")
        print(f"  (minimum 15 words)")
        explanation = await _async_input("  > ")

        elapsed = time.monotonic() - start
        word_count = len(explanation.split())
        passed = word_count >= 15

        if not passed:
            print(
                f"  Insufficient explanation ({word_count} words, need 15). "
                f"Action DENIED."
            )

        return ChallengeResult(
            passed=passed,
            challenge_type=ChallengeType.TEACH_BACK,
            response_time_seconds=round(elapsed, 3),
            questions_asked=1,
            questions_correct=1 if passed else 0,
            details={
                "explanation": explanation.strip(),
                "word_count": word_count,
            },
        )

    async def _render_multi_party(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> ChallengeResult:
        """Multi-party approval: requires 2 independent approvers."""
        start = time.monotonic()
        required_approvers = 2
        approvals = 0
        denials = 0
        sep = "=" * 56

        print()
        print(f"  {sep}")
        print(f"  ATTESTA -- MULTI-PARTY APPROVAL REQUIRED")
        print(f"  {sep}")
        print(f"  Action: {ctx.function_name}")
        print(f"  Risk:   {_risk_bar_plain(risk.score)} {risk.level.value.upper()} ({risk.score:.2f})")
        print(f"  Call:   {_format_call(ctx)}")
        print(f"  {sep}")
        print(f"  This action requires approval from {required_approvers} independent reviewers.")
        print()

        for i in range(required_approvers):
            print(f"  --- Reviewer {i + 1} of {required_approvers} ---")
            response = (await _async_input(f"  Reviewer {i + 1} [a]pprove / [d]eny: ")).strip().lower()
            if response in ("a", "approve", "y", "yes"):
                approvals += 1
                print(f"  Reviewer {i + 1}: APPROVED")
            else:
                denials += 1
                print(f"  Reviewer {i + 1}: DENIED")

        elapsed = time.monotonic() - start
        passed = approvals >= required_approvers

        if passed:
            print(f"\n  All {required_approvers} reviewers approved.")
        else:
            print(f"\n  Multi-party approval FAILED ({approvals}/{required_approvers} approved).")

        return ChallengeResult(
            passed=passed,
            challenge_type=ChallengeType.MULTI_PARTY,
            response_time_seconds=round(elapsed, 3),
            questions_asked=required_approvers,
            questions_correct=approvals,
            details={
                "required_approvers": required_approvers,
                "approvals": approvals,
                "denials": denials,
            },
        )

    # ---- info ---------------------------------------------------------

    async def render_info(self, message: str) -> None:
        print(f"  [attesta] {message}")

    # ---- helpers ------------------------------------------------------

    def _generate_question(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> str:
        """Generate a simple comprehension question from the action context."""
        # Check for path-like arguments
        all_vals = list(ctx.args) + list(ctx.kwargs.values())
        paths = [
            v for v in all_vals
            if isinstance(v, str) and ("/" in v or "\\" in v)
        ]
        lists_in_args = [
            v for v in all_vals
            if isinstance(v, (list, tuple)) and len(v) > 0
        ]

        if paths:
            return "What paths or directories will be affected?"
        if lists_in_args:
            return "What items will this action operate on?"
        return f"What will '{ctx.function_name}' do in this context?"

    @staticmethod
    def _print_explanation(ctx: ActionContext, risk: RiskAssessment) -> None:
        """Print a verbose explanation of the action and risk."""
        print()
        print(f"  --- Explanation ---")
        print(f"  Function: {ctx.function_name}")
        if ctx.function_doc:
            print(f"  Doc:      {ctx.function_doc}")
        print(f"  Full call: {ctx.description}")
        print(f"  Risk score: {risk.score:.4f}")
        print(f"  Risk level: {risk.level.value}")
        if risk.factors:
            print(f"  Factors:")
            for f in risk.factors:
                print(f"    - {f.name}: {f.contribution:.4f} -- {f.description}")
                if f.evidence:
                    print(f"      Evidence: {f.evidence}")
        print(f"  Environment: {ctx.environment}")
        print()


# ===================================================================
# TerminalRenderer -- rich, beautiful terminal UI
# ===================================================================

if _RICH_AVAILABLE:

    class TerminalRenderer(BaseRenderer):
        """Beautiful terminal renderer powered by ``rich``.

        Produces colour-coded panels with risk visualisation bars,
        interactive prompts, countdowns, and comprehension challenges.

        Parameters
        ----------
        console:
            Optional pre-configured ``rich.Console``.  A new stderr
            console is created if not provided.
        min_review_overrides:
            Override per-risk-level minimum review seconds.
        """

        def __init__(
            self,
            console: Console | None = None,
            min_review_overrides: dict[RiskLevel, float] | None = None,
        ) -> None:
            self._console = console or Console(stderr=True)
            self._min_review = {**_MIN_REVIEW_SECONDS}
            if min_review_overrides:
                self._min_review.update(min_review_overrides)

        # ---------------------------------------------------------------
        # Shared UI building blocks
        # ---------------------------------------------------------------

        def _risk_bar(self, score: float, width: int = _BAR_WIDTH) -> Text:
            """Coloured risk bar as a ``rich.Text`` object."""
            level = RiskLevel.from_score(score)
            color = _RISK_COLORS[level]
            filled = round(score * width)
            bar_str = "\u2588" * filled + "\u2591" * (width - filled)
            return Text(bar_str, style=color)

        def _risk_label(self, risk: RiskAssessment) -> Text:
            """Coloured ``LEVEL (0.XX)`` label."""
            color = _RISK_COLORS[risk.level]
            return Text(
                f"{risk.level.value.upper()} ({risk.score:.2f})",
                style=f"bold {color}",
            )

        def _header_title(self, risk: RiskAssessment) -> str:
            """Panel title with optional icon for higher risk levels."""
            icon = _RISK_ICONS.get(risk.level, "")
            parts = []
            if icon:
                parts.append(icon)
            parts.append("ATTESTA")
            if risk.level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                parts.append("\u2500\u2500")
                parts.append(risk.level.value.upper())
                if risk.level == RiskLevel.CRITICAL:
                    # No extra suffix needed; the label already says CRITICAL
                    pass
                else:
                    parts.append("RISK")
            return " ".join(parts)

        def _build_action_lines(
            self, ctx: ActionContext, risk: RiskAssessment
        ) -> Text:
            """Build the action + risk summary as styled Text."""
            color = _RISK_COLORS[risk.level]
            lines = Text()

            # Action line
            lines.append("  Action: ", style="dim")
            lines.append(ctx.function_name, style="bold white")
            lines.append("\n")

            # Risk line
            lines.append("  Risk:   ", style="dim")
            lines.append_text(self._risk_bar(risk.score))
            lines.append(" ")
            lines.append_text(self._risk_label(risk))
            lines.append("\n")

            # Call line
            lines.append("\n")
            lines.append("  Call: ", style="dim")
            lines.append(_format_call(ctx, max_len=50), style="white")
            lines.append("\n")

            return lines

        def _build_factors_table(self, factors: list[RiskFactor]) -> Table:
            """Inner bordered table for risk factor breakdown."""
            table = Table(
                title="Risk Factors",
                title_style="bold dim",
                show_header=False,
                show_edge=True,
                border_style="dim",
                padding=(0, 1),
                expand=True,
            )
            table.add_column("Factor", style="white", ratio=2)
            table.add_column("Bar", ratio=2, no_wrap=True)
            table.add_column("Score", style="dim", ratio=1, justify="right")

            for f in factors:
                bar = self._risk_bar(min(f.contribution, 1.0))
                table.add_row(
                    f.name.replace("_", " ").title(),
                    bar,
                    f"{f.contribution:.2f}",
                )
            return table

        async def _enforce_countdown(self, risk: RiskAssessment) -> None:
            """Show a live countdown if the risk level requires it."""
            min_secs = self._min_review.get(risk.level, 0.0)
            if min_secs > 0:
                await _countdown(min_secs)

        # ---------------------------------------------------------------
        # render_auto_approved  (LOW risk -- compact one-liner)
        # ---------------------------------------------------------------

        async def render_auto_approved(
            self, ctx: ActionContext, risk: RiskAssessment
        ) -> None:
            line = Text()
            line.append("  \u2713 ", style="bold green")
            line.append("AUTO", style="bold green")
            line.append("  ")
            line.append(_format_call(ctx), style="white")
            line.append("  Risk: ", style="dim")
            line.append_text(self._risk_bar(risk.score))
            line.append(" ")
            line.append_text(self._risk_label(risk))
            self._console.print(line)

        # ---------------------------------------------------------------
        # render_approval  (MEDIUM risk -- panel + prompt)
        # ---------------------------------------------------------------

        async def render_approval(
            self, ctx: ActionContext, risk: RiskAssessment
        ) -> Verdict:
            color = _RISK_COLORS[risk.level]
            body = self._build_action_lines(ctx, risk)

            # Factor breakdown if available
            if risk.factors:
                body.append("\n")

            # Menu line
            body.append("\n")
            body.append("  [a]", style="bold cyan")
            body.append(" Approve  ", style="white")
            body.append("[d]", style="bold cyan")
            body.append(" Deny  ", style="white")
            body.append("[e]", style="bold cyan")
            body.append(" Edit  ", style="white")
            body.append("[?]", style="bold cyan")
            body.append(" Explain", style="white")
            body.append("\n")

            panel = Panel(
                body,
                title=self._header_title(risk),
                title_align="left",
                border_style=color,
                padding=(1, 2),
                expand=False,
                width=58,
            )
            self._console.print()
            self._console.print(panel)

            # If there are risk factors, show them beneath
            if risk.factors:
                factors_table = self._build_factors_table(risk.factors)
                factor_panel = Panel(
                    factors_table,
                    border_style="dim",
                    padding=(0, 2),
                    expand=False,
                    width=54,
                )
                self._console.print(Align(factor_panel, align="center"))

            # Countdown if needed
            await self._enforce_countdown(risk)

            # Input loop
            while True:
                response = (await _async_input("  > ")).strip().lower()
                if response in ("a", "approve", "y", "yes"):
                    self._console.print(
                        "  \u2713 Approved", style="bold green"
                    )
                    return Verdict.APPROVED
                if response in ("d", "deny", "n", "no"):
                    self._console.print(
                        "  \u2717 Denied", style="bold red"
                    )
                    return Verdict.DENIED
                if response in ("e", "edit"):
                    self._console.print(
                        "  \u270e Modification requested", style="bold yellow"
                    )
                    return Verdict.MODIFIED
                if response == "?":
                    self._print_explanation_rich(ctx, risk)
                    continue
                self._console.print(
                    "  Enter [bold cyan][a][/]pprove, "
                    "[bold cyan][d][/]eny, "
                    "[bold cyan][e][/]dit, or "
                    "[bold cyan][?][/] explain."
                )

        # ---------------------------------------------------------------
        # render_challenge  (HIGH / CRITICAL -- challenge panels)
        # ---------------------------------------------------------------

        async def render_challenge(
            self,
            ctx: ActionContext,
            risk: RiskAssessment,
            challenge_type: ChallengeType,
        ) -> ChallengeResult:
            if challenge_type == ChallengeType.TEACH_BACK:
                return await self._render_teach_back(ctx, risk)
            if challenge_type == ChallengeType.MULTI_PARTY:
                return await self._render_multi_party(ctx, risk)
            if challenge_type in (
                ChallengeType.QUIZ,
                ChallengeType.CONFIRM,
            ):
                return await self._render_quiz(ctx, risk)
            # Unknown challenge type -- fall through to quiz
            return await self._render_quiz(ctx, risk)

        # -- quiz / comprehension challenge (HIGH) ----------------------

        async def _render_quiz(
            self, ctx: ActionContext, risk: RiskAssessment
        ) -> ChallengeResult:
            start = time.monotonic()
            color = _RISK_COLORS[risk.level]

            # Build panel body
            body = self._build_action_lines(ctx, risk)

            # Risk factors sub-panel rendered inline
            if risk.factors:
                body.append("\n")

            self._console.print()

            panel = Panel(
                body,
                title=self._header_title(risk),
                title_align="left",
                border_style=color,
                padding=(1, 2),
                expand=False,
                width=58,
            )
            self._console.print(panel)

            # Show risk factors in a nested table if present
            if risk.factors:
                factors_table = self._build_factors_table(risk.factors)
                factor_panel = Panel(
                    factors_table,
                    border_style="dim",
                    padding=(0, 2),
                    expand=False,
                    width=54,
                )
                self._console.print(Align(factor_panel, align="center"))

            # Countdown
            await self._enforce_countdown(risk)

            # Comprehension question
            question = self._generate_question(ctx, risk)
            q_body = Text()
            q_body.append("  \u26a1 Comprehension Check:\n", style="bold yellow")
            q_body.append(f"  {question}\n", style="white")

            self._console.print(q_body)

            answer = await _async_input("  > ")
            elapsed = time.monotonic() - start
            passed = len(answer.strip()) > 0

            if passed:
                self._console.print(
                    "  \u2713 Challenge passed", style="bold green"
                )
            else:
                self._console.print(
                    "  \u2717 No answer provided -- DENIED",
                    style="bold red",
                )

            return ChallengeResult(
                passed=passed,
                challenge_type=ChallengeType.QUIZ,
                response_time_seconds=round(elapsed, 3),
                questions_asked=1,
                questions_correct=1 if passed else 0,
                details={"question": question, "answer": answer.strip()},
            )

        # -- teach-back challenge (CRITICAL) ----------------------------

        async def _render_teach_back(
            self, ctx: ActionContext, risk: RiskAssessment
        ) -> ChallengeResult:
            start = time.monotonic()
            color = _RISK_COLORS[RiskLevel.CRITICAL]

            # Build body
            body = Text()
            body.append("\n")
            body.append("  Action: ", style="dim")
            body.append(ctx.function_name, style="bold white")
            body.append("\n")
            body.append("  Risk:   ", style="dim")
            body.append_text(self._risk_bar(risk.score))
            body.append(" ")
            body.append(
                f"CRITICAL ({risk.score:.2f})",
                style="bold bright_red",
            )
            body.append("\n\n")
            body.append("  Call: ", style="dim")
            body.append(_format_call(ctx, max_len=50), style="white")
            body.append("\n\n")
            body.append(
                "  Explain what this action will do and its effects:\n",
                style="bold white",
            )
            body.append("  (minimum 15 words)\n", style="dim italic")
            body.append("\n")
            body.append(
                f"  \u23f1  Minimum review: "
                f"{int(self._min_review.get(RiskLevel.CRITICAL, 30))}s\n",
                style="dim",
            )

            panel = Panel(
                body,
                title=self._header_title(risk),
                title_align="left",
                border_style=color,
                padding=(1, 2),
                expand=False,
                width=58,
            )
            self._console.print()
            self._console.print(panel)

            # Countdown
            await self._enforce_countdown(risk)

            explanation = await _async_input("  > ")
            elapsed = time.monotonic() - start

            word_count = len(explanation.split())
            passed = word_count >= 15

            if passed:
                self._console.print(
                    f"  \u2713 Teach-back accepted ({word_count} words)",
                    style="bold green",
                )
            else:
                self._console.print(
                    f"  \u2717 Insufficient explanation "
                    f"({word_count}/15 words) -- DENIED",
                    style="bold red",
                )

            return ChallengeResult(
                passed=passed,
                challenge_type=ChallengeType.TEACH_BACK,
                response_time_seconds=round(elapsed, 3),
                questions_asked=1,
                questions_correct=1 if passed else 0,
                details={
                    "explanation": explanation.strip(),
                    "word_count": word_count,
                },
            )

        # -- multi-party approval challenge --------------------------------

        async def _render_multi_party(
            self, ctx: ActionContext, risk: RiskAssessment
        ) -> ChallengeResult:
            """Multi-party approval: requires 2 independent approvers."""
            start = time.monotonic()
            required_approvers = 2
            approvals = 0
            denials = 0
            color = _RISK_COLORS[risk.level]

            # Build panel body
            body = Text()
            body.append("\n")
            body.append("  Action: ", style="dim")
            body.append(ctx.function_name, style="bold white")
            body.append("\n")
            body.append("  Risk:   ", style="dim")
            body.append_text(self._risk_bar(risk.score))
            body.append(" ")
            body.append_text(self._risk_label(risk))
            body.append("\n\n")
            body.append("  Call: ", style="dim")
            body.append(_format_call(ctx, max_len=50), style="white")
            body.append("\n\n")
            body.append(
                f"  This action requires approval from {required_approvers} "
                f"independent reviewers.\n",
                style="bold white",
            )

            panel = Panel(
                body,
                title="\u26d4 ATTESTA \u2500\u2500 MULTI-PARTY APPROVAL REQUIRED",
                title_align="left",
                border_style=color,
                padding=(1, 2),
                expand=False,
                width=58,
            )
            self._console.print()
            self._console.print(panel)

            for i in range(required_approvers):
                self._console.print(
                    f"  --- Reviewer {i + 1} of {required_approvers} ---",
                    style="bold dim",
                )
                response = (
                    await _async_input(f"  Reviewer {i + 1} [a]pprove / [d]eny: ")
                ).strip().lower()
                if response in ("a", "approve", "y", "yes"):
                    approvals += 1
                    self._console.print(
                        f"  Reviewer {i + 1}: APPROVED", style="bold green"
                    )
                else:
                    denials += 1
                    self._console.print(
                        f"  Reviewer {i + 1}: DENIED", style="bold red"
                    )

            elapsed = time.monotonic() - start
            passed = approvals >= required_approvers

            if passed:
                self._console.print(
                    f"\n  All {required_approvers} reviewers approved.",
                    style="bold green",
                )
            else:
                self._console.print(
                    f"\n  Multi-party approval FAILED "
                    f"({approvals}/{required_approvers} approved).",
                    style="bold red",
                )

            return ChallengeResult(
                passed=passed,
                challenge_type=ChallengeType.MULTI_PARTY,
                response_time_seconds=round(elapsed, 3),
                questions_asked=required_approvers,
                questions_correct=approvals,
                details={
                    "required_approvers": required_approvers,
                    "approvals": approvals,
                    "denials": denials,
                },
            )

        # ---------------------------------------------------------------
        # render_info
        # ---------------------------------------------------------------

        async def render_info(self, message: str) -> None:
            info_text = Text()
            info_text.append("  \u2139 ", style="bold blue")
            info_text.append("attesta: ", style="bold dim")
            info_text.append(message, style="white")
            self._console.print(info_text)

        # ---------------------------------------------------------------
        # Helpers
        # ---------------------------------------------------------------

        def _generate_question(
            self, ctx: ActionContext, risk: RiskAssessment
        ) -> str:
            """Build a comprehension question from the action context."""
            all_vals = list(ctx.args) + list(ctx.kwargs.values())

            # Look for paths
            paths = [
                v for v in all_vals
                if isinstance(v, str) and ("/" in v or "\\" in v)
            ]
            # Look for list/tuple arguments
            lists_in_args = [
                v for v in all_vals
                if isinstance(v, (list, tuple)) and len(v) > 0
            ]

            if paths:
                return "What directories will be affected?"
            if lists_in_args:
                return "What items will this action operate on?"
            if ctx.kwargs:
                key = next(iter(ctx.kwargs))
                return (
                    f"What is the value of '{key}' and why is it significant?"
                )
            return f"What will '{ctx.function_name}' do and what are the effects?"

        def _print_explanation_rich(
            self, ctx: ActionContext, risk: RiskAssessment
        ) -> None:
            """Pretty-print an expanded explanation of the action."""
            self._console.print()
            self._console.print("  [bold dim]--- Explanation ---[/]")
            self._console.print(
                f"  [dim]Function:[/] [bold]{ctx.function_name}[/]"
            )
            if ctx.function_doc:
                self._console.print(
                    f"  [dim]Doc:[/]      {rich_escape(ctx.function_doc)}"
                )
            self._console.print(
                f"  [dim]Full call:[/] {rich_escape(ctx.description)}"
            )
            self._console.print(
                f"  [dim]Risk score:[/] {risk.score:.4f}"
            )
            self._console.print(
                f"  [dim]Risk level:[/] {risk.level.value}"
            )
            if risk.factors:
                self._console.print("  [dim]Factors:[/]")
                for f in risk.factors:
                    bar = self._risk_bar(min(f.contribution, 1.0))
                    line = Text()
                    line.append(f"    {f.name}: ", style="dim")
                    line.append_text(bar)
                    line.append(
                        f"  {f.contribution:.4f} -- {f.description}"
                    )
                    self._console.print(line)
                    if f.evidence:
                        self._console.print(
                            f"      [dim italic]Evidence: {rich_escape(f.evidence)}[/]"
                        )
            self._console.print(
                f"  [dim]Environment:[/] {ctx.environment}"
            )
            self._console.print()

else:
    # When rich is not available, TerminalRenderer is just PlainRenderer
    TerminalRenderer = PlainRenderer  # type: ignore[misc, assignment]
