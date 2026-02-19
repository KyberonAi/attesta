"""LangChain tool-wrapper example using Attesta risk-based approvals."""

from __future__ import annotations

from attesta import Attesta
from attesta.integrations.langchain import AttestaToolWrapper

try:
    from langchain_core.tools import StructuredTool
except ImportError as exc:  # pragma: no cover - example dependency guard
    raise SystemExit("Install with: pip install 'attesta[langchain,yaml,terminal]'") from exc


attesta = Attesta.from_config("attesta.yaml")


def restart_production_service(service: str) -> str:
    """Restart a production service deployment."""
    return f"Restarted {service}"


def list_active_pods(namespace: str) -> str:
    """Read-only operation for cluster observability."""
    return f"Pods in {namespace}: api-1, api-2"


tools = [
    StructuredTool.from_function(restart_production_service),
    StructuredTool.from_function(list_active_pods),
]

wrapper = AttestaToolWrapper(
    attesta,
    risk_overrides={
        "restart_production_service": "critical",
    },
)

protected_tools = wrapper.wrap_tools(tools)


if __name__ == "__main__":
    print(protected_tools[1].invoke({"namespace": "prod"}))
    print(protected_tools[0].invoke({"service": "payments-api"}))
