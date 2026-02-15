"""Renderers for presenting attesta prompts to operators.

Available renderers:

* :class:`TerminalRenderer` -- Rich terminal UI (falls back to plain text).
* :class:`PlainRenderer` -- Minimal ``print()`` / ``input()`` renderer.
* :class:`BaseRenderer` -- Abstract base class for custom renderers.
"""

from attesta.renderers.base import BaseRenderer
from attesta.renderers.terminal import PlainRenderer, TerminalRenderer
from attesta.renderers.web import WebRenderer

__all__ = [
    "BaseRenderer",
    "PlainRenderer",
    "TerminalRenderer",
    "WebRenderer",
]
