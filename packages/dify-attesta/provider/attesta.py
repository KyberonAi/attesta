"""Attesta tool provider for Dify."""

from typing import Any

from dify_plugin import ToolProvider
from dify_plugin.errors import ToolProviderCredentialValidationError


class AttestaProvider(ToolProvider):
    """Provider that validates Attesta configuration."""

    def _validate_credentials(self, credentials: dict[str, Any]) -> None:
        """Validate that risk_threshold is in [0, 1]."""
        threshold = credentials.get("risk_threshold")
        if threshold is not None:
            try:
                value = float(threshold)
            except (TypeError, ValueError) as e:
                raise ToolProviderCredentialValidationError(
                    "risk_threshold must be a number"
                ) from e
            if not 0.0 <= value <= 1.0:
                raise ToolProviderCredentialValidationError(
                    f"risk_threshold must be between 0 and 1, got {value}"
                )
