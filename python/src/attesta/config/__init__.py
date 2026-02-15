"""Configuration module for attesta.

Exports:
    Policy: Dataclass defining how risk levels map to verification requirements.
    load_config: Load a Policy from a YAML or TOML configuration file.
"""

from attesta.config.loader import Policy, load_config

__all__ = ["Policy", "load_config"]
