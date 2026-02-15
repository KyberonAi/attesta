"""Challenge system for attesta.

This package provides escalating verification challenges that are
presented to human operators based on the assessed risk level of a
pending action:

=============  ==================  ==================================
Risk level     Challenge class     Description
=============  ==================  ==================================
MEDIUM         ConfirmChallenge    Simple Y/N confirmation
HIGH           QuizChallenge       Comprehension questions from context
CRITICAL       TeachBackChallenge  Free-text explanation of effects
CRITICAL+      MultiPartyChallenge 2+ independent human approvals
=============  ==================  ==================================
"""

from attesta.challenges.confirm import ConfirmChallenge
from attesta.challenges.multi_party import ApproverRecord, MultiPartyChallenge
from attesta.challenges.quiz import Question, QuizChallenge
from attesta.challenges.teach_back import TeachBackChallenge
from attesta.challenges.validators import (
    KeywordValidator,
    TeachBackValidator,
)

__all__ = [
    "ApproverRecord",
    "ConfirmChallenge",
    "KeywordValidator",
    "MultiPartyChallenge",
    "Question",
    "QuizChallenge",
    "TeachBackChallenge",
    "TeachBackValidator",
]
