"""Environment auto-detection and risk multipliers.

Detects the deployment environment from environment variables, CI markers,
and hostname patterns.  Used by the gate pipeline to adjust risk scores
based on the operational context.

Detection order (first match wins):

1. ``ATTESTA_ENV`` explicit override.
2. CI markers: ``CI``, ``GITHUB_ACTIONS``, ``GITLAB_CI``, ``JENKINS_URL``.
3. Production markers: ``NODE_ENV=production``, ``FLASK_ENV=production``,
   ``DJANGO_SETTINGS_MODULE`` containing ``prod``.
4. Hostname patterns: ``prod-*``, ``stg-*``, ``staging-*``.
5. Default: ``DEVELOPMENT``.

Usage::

    from attesta.environment import detect_environment, RISK_MULTIPLIERS

    env = detect_environment()
    multiplier = RISK_MULTIPLIERS[env.value]
    adjusted_score = min(1.0, raw_score * multiplier)
"""

from __future__ import annotations

import os
import socket
from enum import Enum

__all__ = ["Environment", "detect_environment", "RISK_MULTIPLIERS"]


class Environment(Enum):
    """Deployment environment classification."""

    PRODUCTION = "production"
    STAGING = "staging"
    CI = "ci"
    DEVELOPMENT = "development"


# Risk multipliers per environment.  Production amplifies risk, development
# reduces it.
RISK_MULTIPLIERS: dict[str, float] = {
    "production": 1.5,
    "staging": 1.2,
    "ci": 1.0,
    "development": 0.8,
}


def detect_environment() -> Environment:
    """Auto-detect the deployment environment.

    The ``ATTESTA_ENV`` environment variable always takes precedence.
    Falls back to heuristic detection from CI markers, production
    variables, and hostname patterns.

    Returns
    -------
    Environment
        The detected (or overridden) environment.
    """
    # 1. Explicit override
    explicit = os.environ.get("ATTESTA_ENV", "").strip().lower()
    if explicit:
        try:
            return Environment(explicit)
        except ValueError:
            pass  # Unknown value, continue with auto-detection

    # 2. CI markers
    ci_vars = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI", "TRAVIS", "BUILDKITE")
    for var in ci_vars:
        if os.environ.get(var):
            return Environment.CI

    # 3. Production markers
    if os.environ.get("NODE_ENV", "").lower() == "production":
        return Environment.PRODUCTION
    if os.environ.get("FLASK_ENV", "").lower() == "production":
        return Environment.PRODUCTION
    django_settings = os.environ.get("DJANGO_SETTINGS_MODULE", "").lower()
    if "prod" in django_settings:
        return Environment.PRODUCTION
    if os.environ.get("RAILS_ENV", "").lower() == "production":
        return Environment.PRODUCTION

    # 4. Hostname patterns
    try:
        hostname = socket.gethostname().lower()
        if hostname.startswith(("prod-", "prod.")):
            return Environment.PRODUCTION
        if hostname.startswith(("stg-", "stg.", "staging-", "staging.")):
            return Environment.STAGING
    except Exception:
        pass

    # 5. Default
    return Environment.DEVELOPMENT
