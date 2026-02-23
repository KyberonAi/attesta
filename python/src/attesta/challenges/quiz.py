"""Quiz challenge for HIGH-risk actions.

Generates 1-3 comprehension questions derived from the actual action
parameters so the operator must demonstrate they understand *what* is
about to happen before approving.
"""

from __future__ import annotations

import asyncio
import os
import random
import re
import time
from dataclasses import dataclass
from typing import Any

from attesta.core.types import (
    ActionContext,
    ChallengeResult,
    ChallengeType,
    RiskAssessment,
)

# ---------------------------------------------------------------------------
# Question model
# ---------------------------------------------------------------------------


@dataclass
class Question:
    """A single quiz question presented to the operator.

    Parameters
    ----------
    text:
        The question text shown to the operator.
    correct_answer:
        The canonical correct answer (case-insensitive comparison).
    options:
        ``None`` for free-text input, or a list of choices for
        multiple-choice (the correct answer **must** appear in the list).
    """

    text: str
    correct_answer: str
    options: list[str] | None = None  # None = free text, list = multiple choice


# ---------------------------------------------------------------------------
# Helpers for question generation
# ---------------------------------------------------------------------------

_PATH_RE = re.compile(
    r"""
    (?:                          # Absolute paths
        /(?:[a-zA-Z0-9._\-]+/)*[a-zA-Z0-9._\-]+
    )
    |
    (?:                          # Windows-style paths
        [A-Z]:\\(?:[^\\\s]+\\)*[^\\\s]+
    )
    |
    (?:                          # Relative paths with at least one separator
        (?:\.\./|\./)(?:[a-zA-Z0-9._\-]+/)*[a-zA-Z0-9._\-]+
    )
    """,
    re.VERBOSE,
)

_SQL_TABLE_RE = re.compile(
    r"""
    (?:FROM|INTO|UPDATE|TABLE|JOIN)\s+
    [`"']?(\w+)[`"']?
    """,
    re.IGNORECASE | re.VERBOSE,
)

_NUMERIC_RE = re.compile(r"^-?\d+(?:\.\d+)?$")


def _flatten_args(ctx: ActionContext) -> list[tuple[str | None, Any]]:
    """Return a flat list of ``(name_or_none, value)`` from args + kwargs."""
    items: list[tuple[str | None, Any]] = [(None, a) for a in ctx.args]
    items.extend(ctx.kwargs.items())
    return items


def _find_paths(values: list[tuple[str | None, Any]]) -> list[str]:
    """Extract file-system paths from argument values."""
    paths: list[str] = []
    for _, val in values:
        if isinstance(val, str):
            paths.extend(_PATH_RE.findall(val))
    return paths


def _find_numbers(values: list[tuple[str | None, Any]]) -> list[tuple[str | None, str]]:
    """Return ``(param_name, numeric_str)`` for numeric args."""
    results: list[tuple[str | None, str]] = []
    for name, val in values:
        str_val = str(val)
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            results.append((name, str_val))
        elif isinstance(val, str) and _NUMERIC_RE.match(val):
            results.append((name, val))
    return results


def _find_sql_tables(values: list[tuple[str | None, Any]]) -> list[str]:
    """Extract SQL table names from string arguments."""
    tables: list[str] = []
    for _, val in values:
        if isinstance(val, str):
            tables.extend(_SQL_TABLE_RE.findall(val))
    return list(dict.fromkeys(tables))  # dedupe, preserve order


def _split_function_name(name: str) -> list[str]:
    """Split a function name into meaningful words.

    Handles ``snake_case``, ``camelCase``, and ``PascalCase``.
    """
    # Split on underscores first
    parts = name.replace("-", "_").split("_")
    # Then split camelCase/PascalCase within each part
    words: list[str] = []
    for part in parts:
        tokens = re.sub(r"([a-z])([A-Z])", r"\1 \2", part).split()
        words.extend(t.lower() for t in tokens if t)
    return words


def _make_wrong_path(correct: str) -> str:
    """Generate a plausible but incorrect path for a distractor."""
    dirname = os.path.dirname(correct) or "/"
    basename = os.path.basename(correct)
    distractors = [
        os.path.join(dirname, "tmp_" + basename),
        os.path.join(os.path.dirname(dirname) or "/", basename),
        correct + ".bak",
    ]
    return random.choice(distractors)


# ---------------------------------------------------------------------------
# QuizChallenge
# ---------------------------------------------------------------------------


class QuizChallenge:
    """Comprehension quiz for HIGH-risk actions.

    Analyses the :class:`ActionContext` to programmatically generate 1-3
    multiple-choice or fill-in-the-blank questions about the pending action.
    The operator must answer at least one question correctly to pass.

    Parameters
    ----------
    max_questions:
        Upper bound on the number of questions to generate (1-3).
    min_correct:
        Minimum correct answers required to pass.
    min_review_seconds:
        Minimum wall-clock seconds before the first question is shown.
    """

    def __init__(
        self,
        max_questions: int = 3,
        min_correct: int = 1,
        min_review_seconds: float = 10.0,
    ) -> None:
        self.max_questions = max(1, min(max_questions, 3))
        self.min_correct = max(1, min_correct)
        self.min_review_seconds = min_review_seconds

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.QUIZ

    # -- question generation ----------------------------------------------

    def generate_questions(self, ctx: ActionContext, risk: RiskAssessment) -> list[Question]:
        """Build a list of questions from the action context.

        Strategy priority:
        1. File-path arguments   -> "What directory / file will be affected?"
        2. Numeric arguments     -> "What is the value of <param>?"
        3. SQL-like strings      -> "Which table will be affected?"
        4. Fallback              -> "What will this function do?" (from name)
        """
        flat = _flatten_args(ctx)
        questions: list[Question] = []

        # Strategy 1: file paths
        paths = _find_paths(flat)
        if paths:
            path = paths[0]
            dirname = os.path.dirname(path) or "/"
            basename = os.path.basename(path)
            # Ask about the directory
            wrong_dirs = [
                os.path.dirname(os.path.dirname(path)) or "/",
                "/tmp",
                "/var/log",
            ]
            # Filter out correct answer from distractors and dedupe
            wrong_dirs = list(dict.fromkeys(d for d in wrong_dirs if d != dirname))
            options = [dirname] + wrong_dirs[:3]
            random.shuffle(options)
            questions.append(
                Question(
                    text="What directory will be affected by this action?",
                    correct_answer=dirname,
                    options=options,
                )
            )
            # Optionally ask about the specific file
            if len(questions) < self.max_questions and basename:
                questions.append(
                    Question(
                        text="Which file will this action operate on?",
                        correct_answer=basename,
                        options=None,  # free text
                    )
                )

        # Strategy 2: numeric arguments
        numbers = _find_numbers(flat)
        if numbers and len(questions) < self.max_questions:
            name, num_str = numbers[0]
            label = f"parameter '{name}'" if name else "this action"
            # Create wrong options
            try:
                num_val = float(num_str)
                wrong = [
                    str(int(num_val * 2)) if num_val == int(num_val) else f"{num_val * 2:.2f}",
                    str(int(num_val + 10)) if num_val == int(num_val) else f"{num_val + 10:.2f}",
                    str(max(0, int(num_val - 1))) if num_val == int(num_val) else f"{max(0.0, num_val - 1):.2f}",
                ]
            except ValueError:
                wrong = ["0", "100", "42"]

            wrong = list(dict.fromkeys(w for w in wrong if w != num_str))[:3]
            options = [num_str] + wrong
            random.shuffle(options)
            questions.append(
                Question(
                    text=f"What is the numeric value for {label}?",
                    correct_answer=num_str,
                    options=options,
                )
            )

        # Strategy 3: SQL table names
        tables = _find_sql_tables(flat)
        if tables and len(questions) < self.max_questions:
            table = tables[0]
            wrong_tables = ["users", "logs", "tmp_data", "sessions", "config"]
            wrong_tables = [t for t in wrong_tables if t.lower() != table.lower()][:3]
            options = [table] + wrong_tables
            random.shuffle(options)
            questions.append(
                Question(
                    text="Which database table will be affected?",
                    correct_answer=table,
                    options=options,
                )
            )

        # Strategy 4 (fallback): function-name comprehension
        if not questions:
            words = _split_function_name(ctx.function_name)
            action_verb = words[0] if words else "perform"
            target = " ".join(words[1:]) if len(words) > 1 else "an operation"
            correct = f"{action_verb} {target}"

            wrong = [
                f"read {target}",
                f"list {target}",
                f"validate {target}",
            ]
            wrong = [w for w in wrong if w != correct][:3]
            options = [correct] + wrong
            random.shuffle(options)
            questions.append(
                Question(
                    text=f"What will the function '{ctx.function_name}' do?",
                    correct_answer=correct,
                    options=options,
                )
            )

        return questions[: self.max_questions]

    # -- presentation -----------------------------------------------------

    async def present(self, ctx: ActionContext, risk: RiskAssessment) -> ChallengeResult:
        """Present the quiz to the operator and collect answers."""
        start = time.monotonic()
        loop = asyncio.get_running_loop()

        # -- render action summary ----------------------------------------
        separator = "=" * 60
        print(f"\n{separator}")
        print("  QUIZ CHALLENGE  --  HIGH RISK ACTION")
        print(f"{separator}")
        print(f"  Action: {ctx.function_name}")
        print(f"  Risk:   {risk.level.value.upper()} ({risk.score:.2f})")
        if ctx.function_doc:
            print(f"  Desc:   {ctx.function_doc}")
        print(f"  Call:   {ctx.description}")
        print(f"{separator}")

        # -- enforce minimum review time ----------------------------------
        elapsed = time.monotonic() - start
        if elapsed < self.min_review_seconds:
            remaining = self.min_review_seconds - elapsed
            print(f"  [Review the action for {remaining:.0f}s before answering...]")
            await asyncio.sleep(remaining)

        # -- generate and ask questions -----------------------------------
        questions = self.generate_questions(ctx, risk)
        correct_count = 0

        def _read_input(prompt: str) -> str:
            try:
                return input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                return ""

        for idx, question in enumerate(questions, start=1):
            print(f"\n  Question {idx}/{len(questions)}: {question.text}")

            if question.options:
                for letter_idx, option in enumerate(question.options):
                    letter = chr(ord("A") + letter_idx)
                    print(f"    {letter}) {option}")
                raw = await loop.run_in_executor(None, lambda: _read_input("  Your answer (letter or value): "))
                # Accept either the letter label or the literal value
                answer = raw
                if len(raw) == 1 and raw.upper().isalpha():
                    choice_idx = ord(raw.upper()) - ord("A")
                    if 0 <= choice_idx < len(question.options):
                        answer = question.options[choice_idx]
            else:
                raw = await loop.run_in_executor(None, lambda: _read_input("  Your answer: "))
                answer = raw

            if answer.lower() == question.correct_answer.lower():
                correct_count += 1
                print("  Correct.")
            else:
                print(f"  Incorrect. (expected: {question.correct_answer})")

        elapsed = time.monotonic() - start
        passed = correct_count >= self.min_correct

        print(f"\n  Result: {correct_count}/{len(questions)} correct -- {'PASSED' if passed else 'FAILED'}")

        return ChallengeResult(
            passed=passed,
            challenge_type=self.challenge_type,
            response_time_seconds=elapsed,
            questions_asked=len(questions),
            questions_correct=correct_count,
            details={
                "questions": [
                    {
                        "text": q.text,
                        "correct_answer": q.correct_answer,
                        "options": q.options,
                    }
                    for q in questions
                ],
            },
        )
