"""Framework integrations for attesta.

Provides drop-in integration classes for popular AI-agent frameworks:

* **LangChain / LangGraph** -- :class:`AttestaToolWrapper`, :func:`attesta_node`
* **OpenAI Agents SDK** -- :func:`attesta_approval_handler`, :class:`AttestaGuardrail`
* **CrewAI** -- :class:`AttestaHumanInput`
* **Anthropic Claude** -- :class:`AttestaToolGate`
* **MCP** -- :func:`attesta_tool_handler`, :class:`MCPProxy`

Each integration is lazily imported so that unused framework dependencies are
never required at import time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

# Re-export all public integration classes for convenience:
#     from attesta.integrations import AttestaToolWrapper
#
# Imports are lazy so that missing optional dependencies (langchain, openai,
# crewai, anthropic, mcp) only cause errors when the user actually tries to
# instantiate the corresponding class.

if TYPE_CHECKING:
    from attesta.integrations.anthropic import AttestaToolGate
    from attesta.integrations.crewai import AttestaHumanInput
    from attesta.integrations.langchain import (
        AttestaToolWrapper,
        attesta_node,
    )
    from attesta.integrations.mcp import (
        MCPProxy,
        attesta_tool_handler,
    )
    from attesta.integrations.openai_sdk import (
        AttestaGuardrail,
        attesta_approval_handler,
    )


def __getattr__(name: str) -> object:  # noqa: C901
    """Lazy-load integration symbols on first access."""
    if name == "AttestaToolWrapper":
        from attesta.integrations.langchain import AttestaToolWrapper

        return AttestaToolWrapper

    if name == "attesta_node":
        from attesta.integrations.langchain import attesta_node

        return attesta_node

    if name == "attesta_approval_handler":
        from attesta.integrations.openai_sdk import attesta_approval_handler

        return attesta_approval_handler

    if name == "AttestaGuardrail":
        from attesta.integrations.openai_sdk import AttestaGuardrail

        return AttestaGuardrail

    if name == "AttestaHumanInput":
        from attesta.integrations.crewai import AttestaHumanInput

        return AttestaHumanInput

    if name == "AttestaToolGate":
        from attesta.integrations.anthropic import AttestaToolGate

        return AttestaToolGate

    if name == "attesta_tool_handler":
        from attesta.integrations.mcp import attesta_tool_handler

        return attesta_tool_handler

    if name == "MCPProxy":
        from attesta.integrations.mcp import MCPProxy

        return MCPProxy

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # LangChain / LangGraph
    "AttestaToolWrapper",
    "attesta_node",
    # OpenAI Agents SDK
    "attesta_approval_handler",
    "AttestaGuardrail",
    # CrewAI
    "AttestaHumanInput",
    # Anthropic Claude
    "AttestaToolGate",
    # MCP (Model Context Protocol)
    "attesta_tool_handler",
    "MCPProxy",
]
