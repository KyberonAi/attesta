"""Community / user-supplied domain profiles.

This package provides the :func:`load_preset` and :func:`list_presets`
APIs.  In the open-source release no built-in presets are shipped; you
can create your own :class:`~attesta.domains.profile.DomainProfile`
instances and register them here, or point to a third-party preset
package.

To register a custom preset::

    from attesta.domains.presets import register_preset
    from attesta.domains.profile import DomainProfile

    my_profile = DomainProfile(
        name="my-industry",
        display_name="My Industry",
        description="Custom risk profile.",
    )
    register_preset(my_profile)

    # Now load_preset("my-industry") works.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from attesta.domains.profile import DomainProfile

__all__ = [
    "load_preset",
    "list_presets",
    "register_preset",
    "PRESET_PROFILES",
]

# ---------------------------------------------------------------------------
# Lookup table (empty by default; populated by register_preset())
# ---------------------------------------------------------------------------

PRESET_PROFILES: dict[str, DomainProfile] = {}

# Convenience aliases for user-registered presets.
_ALIASES: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def register_preset(
    profile: DomainProfile,
    aliases: list[str] | None = None,
) -> None:
    """Register a domain profile as a loadable preset.

    Args:
        profile: The :class:`~attesta.domains.profile.DomainProfile` to register.
        aliases: Optional list of alternative names that resolve to this profile.

    Raises:
        ValueError: If a profile with the same name is already registered.
    """
    if profile.name in PRESET_PROFILES:
        raise ValueError(
            f"Preset profile '{profile.name}' is already registered. "
            f"Remove it first or choose a different name."
        )
    PRESET_PROFILES[profile.name] = profile
    for alias in (aliases or []):
        _ALIASES[alias.lower().strip()] = profile.name


def load_preset(name: str) -> DomainProfile:
    """Load a registered domain profile by name.

    The *name* is case-insensitive and supports aliases registered via
    :func:`register_preset`.

    Args:
        name: The profile name or an alias.

    Returns:
        The corresponding :class:`~attesta.domains.profile.DomainProfile`.

    Raises:
        KeyError: If *name* does not match any registered profile or alias.
    """
    key = name.lower().strip()

    # Resolve alias to canonical name.
    canonical = _ALIASES.get(key, key)

    if canonical in PRESET_PROFILES:
        return PRESET_PROFILES[canonical]

    available = sorted(set(list(PRESET_PROFILES.keys()) + list(_ALIASES.keys())))
    if available:
        hint = f"Available presets and aliases: {', '.join(available)}"
    else:
        hint = (
            "No presets are currently registered. "
            "Use register_preset() to add domain profiles, "
            "or create a DomainProfile directly."
        )
    raise KeyError(f"No preset profile named '{name}'. {hint}")


def list_presets() -> list[str]:
    """Return a sorted list of all registered preset profile names.

    This includes only the canonical names (not aliases).
    """
    return sorted(PRESET_PROFILES.keys())
