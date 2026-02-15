"""Command-line interface for attesta.

Entry point: ``attesta``, registered via pyproject.toml ``[project.scripts]``.

Subcommands
-----------
- ``attesta init``              -- scaffold an attesta.yaml in the current directory
- ``attesta audit verify``      -- verify hash-chain integrity of the audit log
- ``attesta audit stats``       -- print approval statistics
- ``attesta audit rubber-stamps`` -- list entries flagged as rubber stamps
- ``attesta trust show <id>``   -- display trust profile for one agent
- ``attesta trust list``        -- list all known agents and their trust scores
- ``attesta trust revoke <id>`` -- revoke trust for an agent
- ``attesta mcp wrap -- <cmd>`` -- wrap any MCP server with Attesta approval
- ``attesta version``           -- print the package version
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import TextIO


# ---------------------------------------------------------------------------
# ANSI colour helpers (no external deps)
# ---------------------------------------------------------------------------

_SUPPORTS_COLOR: bool | None = None


def _color_supported(stream: TextIO = sys.stdout) -> bool:
    """Return True if *stream* is a colour-capable terminal."""
    global _SUPPORTS_COLOR
    if _SUPPORTS_COLOR is not None:
        return _SUPPORTS_COLOR
    try:
        _SUPPORTS_COLOR = hasattr(stream, "isatty") and stream.isatty()
    except Exception:
        _SUPPORTS_COLOR = False
    return _SUPPORTS_COLOR


def _ansi(code: str, text: str) -> str:
    if _color_supported():
        return f"\033[{code}m{text}\033[0m"
    return text


def _bold(text: str) -> str:
    return _ansi("1", text)


def _green(text: str) -> str:
    return _ansi("32", text)


def _red(text: str) -> str:
    return _ansi("31", text)


def _yellow(text: str) -> str:
    return _ansi("33", text)


def _cyan(text: str) -> str:
    return _ansi("36", text)


def _dim(text: str) -> str:
    return _ansi("2", text)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_DEFAULT_AUDIT_PATH = Path(".attesta/audit.jsonl")
_DEFAULT_TRUST_PATH = Path(".attesta/trust.json")
_DEFAULT_CONFIG_NAME = "attesta.yaml"


def _resolve_audit_path(args: argparse.Namespace) -> Path:
    """Return the audit log path from CLI flags or the default."""
    return Path(getattr(args, "audit_log", None) or _DEFAULT_AUDIT_PATH)


def _resolve_trust_path(args: argparse.Namespace) -> Path:
    """Return the trust store path from CLI flags or the default."""
    return Path(getattr(args, "trust_store", None) or _DEFAULT_TRUST_PATH)


def _err(message: str) -> None:
    """Print an error message to stderr and exit with code 1."""
    print(f"{_red('error')}: {message}", file=sys.stderr)
    sys.exit(1)


def _warn(message: str) -> None:
    """Print a warning message to stderr."""
    print(f"{_yellow('warning')}: {message}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Default config template
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG = """\
# attesta configuration
# Docs: https://attesta.dev

# Domain profile for industry-specific risk scoring.
# Register custom profiles with register_preset(), then activate here.
# domain: my-domain

policy:
  # How long a reviewer must spend (seconds) per risk level
  minimum_review_seconds:
    low: 0
    medium: 3
    high: 10
    critical: 30

  # Number of approvers required for each risk level
  require_multi_party:
    critical: 2

  # What happens on timeout: deny | allow | escalate
  fail_mode: deny
  timeout_seconds: 300

trust:
  # Max risk reduction from high trust (0-1)
  influence: 0.3
  # Trust score ceiling
  ceiling: 0.9
  # Starting trust for unknown agents
  initial_score: 0.3
  # Trust decay per day of inactivity
  decay_rate: 0.01

risk:
  # Map action names to explicit risk levels
  overrides: {}
  #   deploy_production: critical
  #   restart_service: high

  # Patterns that amplify risk
  amplifiers: []
  #   - pattern: ".*production.*"
  #     boost: 0.3
  #   - pattern: ".*delete.*"
  #     boost: 0.2
"""


# ---------------------------------------------------------------------------
# Subcommand: init
# ---------------------------------------------------------------------------

def _cmd_init(args: argparse.Namespace) -> None:
    """Create an attesta.yaml in the current working directory."""
    dest = Path.cwd() / _DEFAULT_CONFIG_NAME

    if dest.exists() and not getattr(args, "force", False):
        _err(
            f"{_DEFAULT_CONFIG_NAME} already exists in this directory. "
            "Use --force to overwrite."
        )

    dest.write_text(_DEFAULT_CONFIG, encoding="utf-8")
    print(f"{_green('Created')} {dest}")
    print(f"Edit the file to customise policies, trust settings, and risk overrides.")


# ---------------------------------------------------------------------------
# Subcommand: audit verify
# ---------------------------------------------------------------------------

def _cmd_audit_verify(args: argparse.Namespace) -> None:
    """Verify the integrity of the hash-chained audit log."""
    from attesta.core.audit import AuditLogger

    audit_path = _resolve_audit_path(args)
    if not audit_path.exists():
        _err(f"Audit log not found: {audit_path}")

    audit = AuditLogger(path=audit_path)
    intact, total, broken = audit.verify_chain()

    print(f"Audit log : {audit_path}")
    print(f"Entries   : {total}")

    if intact:
        print(f"Status    : {_green('INTACT')} -- all hashes verified")
    else:
        print(f"Status    : {_red('BROKEN')} -- {len(broken)} invalid link(s)")
        print(f"Broken at : {', '.join(str(i) for i in broken)}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Subcommand: audit stats
# ---------------------------------------------------------------------------

def _cmd_audit_stats(args: argparse.Namespace) -> None:
    """Print approval statistics from the audit log."""
    from attesta.core.audit import AuditEntry

    audit_path = _resolve_audit_path(args)
    if not audit_path.exists():
        _err(f"Audit log not found: {audit_path}")

    entries = _read_all_entries(audit_path)

    if not entries:
        print("No audit entries found.")
        return

    total = len(entries)
    approved = sum(1 for e in entries if e.verdict == "approved")
    denied = sum(1 for e in entries if e.verdict == "denied")
    modified = sum(1 for e in entries if e.verdict == "modified")
    escalated = sum(1 for e in entries if e.verdict == "escalated")
    timed_out = sum(1 for e in entries if e.verdict == "timed_out")

    review_times = [
        e.review_duration_seconds
        for e in entries
        if e.review_duration_seconds > 0
    ]
    avg_review = (
        sum(review_times) / len(review_times) if review_times else 0.0
    )

    # Rubber stamp rate: approved high/critical with fast review
    from attesta.core.audit import AuditLogger as _AL

    audit = _AL(path=audit_path)
    rubber_stamps = audit.find_rubber_stamps()
    rubber_stamp_rate = (
        (len(rubber_stamps) / approved * 100) if approved > 0 else 0.0
    )

    # Risk level distribution
    risk_counts: dict[str, int] = {}
    for e in entries:
        level = e.risk_level or "unknown"
        risk_counts[level] = risk_counts.get(level, 0) + 1

    print(_bold("Audit Statistics"))
    print(f"{'':>2}Log file             : {audit_path}")
    print()
    print(_bold("  Totals"))
    print(f"{'':>4}Total entries       : {total}")
    print(f"{'':>4}Approved           : {_green(str(approved))}")
    print(f"{'':>4}Denied             : {_red(str(denied))}")
    if modified:
        print(f"{'':>4}Modified           : {_yellow(str(modified))}")
    if escalated:
        print(f"{'':>4}Escalated          : {_yellow(str(escalated))}")
    if timed_out:
        print(f"{'':>4}Timed out          : {_dim(str(timed_out))}")
    print()
    print(_bold("  Review Quality"))
    print(f"{'':>4}Avg review time    : {avg_review:.1f}s")
    print(f"{'':>4}Rubber stamp rate  : {_format_rate(rubber_stamp_rate)}")
    print(f"{'':>4}Rubber stamps      : {len(rubber_stamps)}")
    print()
    print(_bold("  Risk Distribution"))
    for level in ("low", "medium", "high", "critical"):
        count = risk_counts.get(level, 0)
        label = _colorize_risk(level)
        print(f"{'':>4}{label:<24s}: {count}")
    unknown = risk_counts.get("unknown", 0)
    if unknown:
        print(f"{'':>4}{'unknown':<17s}: {unknown}")


def _format_rate(rate: float) -> str:
    """Format a percentage with colour based on severity."""
    text = f"{rate:.1f}%"
    if rate > 20:
        return _red(text)
    if rate > 10:
        return _yellow(text)
    return _green(text)


def _colorize_risk(level: str) -> str:
    """Return a coloured risk level string."""
    level_lower = level.lower()
    if level_lower == "critical":
        return _red(level.capitalize())
    if level_lower == "high":
        return _yellow(level.capitalize())
    if level_lower == "medium":
        return _cyan(level.capitalize())
    return _green(level.capitalize())


# ---------------------------------------------------------------------------
# Subcommand: audit rubber-stamps
# ---------------------------------------------------------------------------

def _cmd_audit_rubber_stamps(args: argparse.Namespace) -> None:
    """List audit entries flagged as rubber stamps."""
    from attesta.core.audit import AuditLogger

    audit_path = _resolve_audit_path(args)
    if not audit_path.exists():
        _err(f"Audit log not found: {audit_path}")

    max_seconds = getattr(args, "max_seconds", 5.0)
    min_risk = getattr(args, "min_risk", "high")

    audit = AuditLogger(path=audit_path)
    stamps = audit.find_rubber_stamps(
        max_review_seconds=max_seconds,
        min_risk=min_risk,
    )

    if not stamps:
        print(_green("No rubber stamps found."))
        return

    print(_bold(f"Found {len(stamps)} rubber stamp(s):"))
    print()

    for i, entry in enumerate(stamps, 1):
        risk_label = _colorize_risk(entry.risk_level)
        print(
            f"  {_dim(str(i) + '.')} {entry.action_name or '(unnamed)'}"
            f"  [{risk_label}]"
            f"  {entry.review_duration_seconds:.1f}s review"
            f"  {_dim(entry.entry_id[:12] + '...')}"
        )
        if entry.agent_id:
            print(f"     Agent: {entry.agent_id}")
        if entry.intercepted_at:
            print(f"     Time:  {entry.intercepted_at}")
        print()


# ---------------------------------------------------------------------------
# Subcommand: audit export
# ---------------------------------------------------------------------------

def _cmd_audit_export(args: argparse.Namespace) -> None:
    """Export audit entries to CSV or JSON."""
    from attesta.core.audit import AuditLogger

    audit_path = _resolve_audit_path(args)
    if not audit_path.exists():
        _err(f"Audit log not found: {audit_path}")

    audit = AuditLogger(path=audit_path)

    fmt = getattr(args, "format", "csv")
    output_path = getattr(args, "output", None)

    # Build filters
    filters: dict[str, str] = {}
    since = getattr(args, "since", None)
    if since:
        filters["from_date"] = since
    agent = getattr(args, "agent", None)
    if agent:
        filters["agent_id"] = agent

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            audit.export(format=fmt, output=f, **filters)
        print(f"{_green('Exported')} audit entries to {output_path} ({fmt.upper()})")
    else:
        audit.export(format=fmt, **filters)


# ---------------------------------------------------------------------------
# Subcommand: trust show
# ---------------------------------------------------------------------------

def _cmd_trust_show(args: argparse.Namespace) -> None:
    """Show the trust profile for a single agent."""
    from attesta.core.trust import TrustEngine

    trust_path = _resolve_trust_path(args)
    agent_id: str = args.agent_id

    if not trust_path.exists():
        _err(f"Trust store not found: {trust_path}")

    engine = TrustEngine(storage_path=trust_path)
    profile = engine.get_profile(agent_id)

    # Check if the agent actually exists in the stored data (get_profile
    # creates a default on the fly, so we verify against the file).
    stored = _load_trust_data(trust_path)
    if agent_id not in stored:
        _err(f"Agent '{agent_id}' not found in trust store.")

    trust_score = engine.compute_trust(agent_id)

    print(_bold(f"Trust Profile: {agent_id}"))
    print()
    print(f"  Overall score  : {_colorize_score(trust_score)}")
    print(f"  Stored score   : {_colorize_score(profile.overall_score)}")
    print(f"  Incidents      : {profile.incidents}")
    print(f"  Created        : {profile.created_at.isoformat()}")
    last_action = (
        profile.last_action_at.isoformat() if profile.last_action_at else "never"
    )
    print(f"  Last action    : {last_action}")

    if profile.domain_scores:
        print()
        print(_bold("  Domain Scores"))
        for domain, score in sorted(profile.domain_scores.items()):
            print(f"    {domain:<20s}: {_colorize_score(score)}")

    agent_data = stored.get(agent_id, {})
    history_count = agent_data.get("history_count", len(profile.history))
    print()
    print(f"  History entries : {history_count}")


def _colorize_score(score: float) -> str:
    """Return a coloured trust score string."""
    text = f"{score:.3f}"
    if score >= 0.7:
        return _green(text)
    if score >= 0.4:
        return _yellow(text)
    return _red(text)


# ---------------------------------------------------------------------------
# Subcommand: trust list
# ---------------------------------------------------------------------------

def _cmd_trust_list(args: argparse.Namespace) -> None:
    """List all agents and their trust scores."""
    from attesta.core.trust import TrustEngine

    trust_path = _resolve_trust_path(args)

    if not trust_path.exists():
        _err(f"Trust store not found: {trust_path}")

    stored = _load_trust_data(trust_path)

    if not stored:
        print("No agents found in trust store.")
        return

    engine = TrustEngine(storage_path=trust_path)

    # Table header
    header = f"  {'Agent ID':<30s} {'Score':>7s} {'Incidents':>10s} {'Last Active':<20s}"
    print(_bold("Agents"))
    print()
    print(_dim(header))
    print(_dim("  " + "-" * (len(header) - 2)))

    for agent_id in sorted(stored.keys()):
        info = stored[agent_id]
        score = engine.compute_trust(agent_id)
        incidents = info.get("incidents", 0)
        last_active = info.get("last_action_at") or "never"
        if last_active != "never":
            # Show just the date portion for readability
            try:
                dt = datetime.fromisoformat(last_active)
                last_active = dt.strftime("%Y-%m-%d %H:%M")
            except ValueError:
                pass

        score_str = _colorize_score(score)
        incidents_str = _red(str(incidents)) if incidents > 0 else str(incidents)

        print(f"  {agent_id:<30s} {score_str:>7s} {incidents_str:>10s} {last_active:<20s}")

    print()
    print(f"  {_dim(f'{len(stored)} agent(s) total')}")


# ---------------------------------------------------------------------------
# Subcommand: trust revoke
# ---------------------------------------------------------------------------

def _cmd_trust_revoke(args: argparse.Namespace) -> None:
    """Revoke all trust for an agent."""
    from attesta.core.trust import TrustEngine

    trust_path = _resolve_trust_path(args)
    agent_id: str = args.agent_id

    if not trust_path.exists():
        _err(f"Trust store not found: {trust_path}")

    stored = _load_trust_data(trust_path)
    if agent_id not in stored:
        _err(f"Agent '{agent_id}' not found in trust store.")

    if not getattr(args, "yes", False):
        try:
            answer = input(
                f"Revoke all trust for agent '{agent_id}'? "
                f"This cannot be undone. [y/N] "
            )
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(130)
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return

    engine = TrustEngine(storage_path=trust_path)
    engine.revoke(agent_id)
    print(f"{_red('Revoked')} trust for agent '{agent_id}'.")
    print(f"  New score: {_colorize_score(0.0)}")


# ---------------------------------------------------------------------------
# Subcommand: mcp wrap
# ---------------------------------------------------------------------------

def _cmd_mcp_wrap(args: argparse.Namespace) -> None:
    """Wrap any MCP server with Attesta approval (proxy mode).

    Starts a stdio proxy between the MCP client (editor/IDE) and the
    upstream MCP server.  Every ``tools/call`` request is evaluated by
    Attesta before being forwarded.  Denied calls never reach the upstream
    server.
    """
    from attesta import Attesta
    from attesta.integrations.mcp import MCPProxy

    upstream = list(getattr(args, "upstream_command", []))

    # Strip the leading "--" that argparse may capture.
    while upstream and upstream[0] == "--":
        upstream.pop(0)

    if not upstream:
        _err(
            "No upstream MCP server command provided.\n"
            "Usage: attesta mcp wrap -- <command> [args...]\n"
            "Example: attesta mcp wrap -- npx @modelcontextprotocol/server-filesystem /tmp"
        )

    # Load Attesta config.
    config_path = Path(getattr(args, "config", None) or _DEFAULT_CONFIG_NAME)
    if config_path.exists():
        attesta = Attesta.from_config(config_path)
        print(
            f"[attesta] Loaded config from {config_path}",
            file=sys.stderr, flush=True,
        )
    else:
        attesta = Attesta()
        print(
            f"[attesta] No config found ({config_path}), using defaults",
            file=sys.stderr, flush=True,
        )

    # Parse risk overrides from --risk-override flags.
    risk_overrides: dict[str, str] = {}
    for item in getattr(args, "risk_override", None) or []:
        if "=" not in item:
            _warn(f"Ignoring malformed --risk-override: {item!r} (expected tool=level)")
            continue
        tool, level = item.split("=", 1)
        risk_overrides[tool.strip()] = level.strip()

    proxy = MCPProxy(
        attesta=attesta,
        upstream_command=upstream,
        risk_overrides=risk_overrides,
    )

    proxy.run()


# ---------------------------------------------------------------------------
# Subcommand: version
# ---------------------------------------------------------------------------

def _cmd_version(args: argparse.Namespace) -> None:
    """Print the attesta version."""
    from attesta import __version__

    print(f"attesta {__version__}")


# ---------------------------------------------------------------------------
# Helpers for reading raw data
# ---------------------------------------------------------------------------

def _read_all_entries(audit_path: Path) -> list:
    """Read all audit entries from the JSONL file."""
    from attesta.core.audit import AuditEntry

    entries = []
    with audit_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(AuditEntry.from_json(line))
            except (json.JSONDecodeError, TypeError):
                continue
    return entries


def _load_trust_data(trust_path: Path) -> dict:
    """Load raw trust data from the JSON store."""
    try:
        return json.loads(trust_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        _err(f"Failed to read trust store {trust_path}: {exc}")
        return {}  # unreachable, _err calls sys.exit


# ---------------------------------------------------------------------------
# Argument parser construction
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="attesta",
        description="attesta -- human-in-the-loop approval for AI agents",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # ---- attesta init ----
    init_parser = subparsers.add_parser(
        "init",
        help="Create an attesta.yaml config in the current directory",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing attesta.yaml",
    )
    init_parser.set_defaults(func=_cmd_init)

    # ---- attesta audit ----
    audit_parser = subparsers.add_parser(
        "audit",
        help="Audit log inspection commands",
    )
    audit_parser.add_argument(
        "--log",
        dest="audit_log",
        default=None,
        metavar="PATH",
        help=f"Path to audit log (default: {_DEFAULT_AUDIT_PATH})",
    )
    audit_sub = audit_parser.add_subparsers(dest="audit_command", metavar="<subcommand>")

    # attesta audit verify
    verify_parser = audit_sub.add_parser(
        "verify",
        help="Verify hash-chain integrity of the audit log",
    )
    verify_parser.set_defaults(func=_cmd_audit_verify)

    # attesta audit stats
    stats_parser = audit_sub.add_parser(
        "stats",
        help="Show approval statistics",
    )
    stats_parser.set_defaults(func=_cmd_audit_stats)

    # attesta audit export
    export_parser = audit_sub.add_parser(
        "export",
        help="Export audit entries to CSV or JSON",
    )
    export_parser.add_argument(
        "--format", "-f",
        choices=("csv", "json"),
        default="csv",
        help="Output format (default: csv)",
    )
    export_parser.add_argument(
        "--output", "-o",
        default=None,
        metavar="FILE",
        help="Output file (default: stdout)",
    )
    export_parser.add_argument(
        "--since",
        default=None,
        metavar="DATE",
        help="Only include entries after this ISO-8601 date",
    )
    export_parser.add_argument(
        "--agent",
        default=None,
        metavar="AGENT_ID",
        help="Only include entries for this agent",
    )
    export_parser.set_defaults(func=_cmd_audit_export)

    # attesta audit rubber-stamps
    rs_parser = audit_sub.add_parser(
        "rubber-stamps",
        help="List entries flagged as rubber stamps",
    )
    rs_parser.add_argument(
        "--max-seconds",
        type=float,
        default=5.0,
        help="Maximum review time to flag (default: 5.0s)",
    )
    rs_parser.add_argument(
        "--min-risk",
        choices=("low", "medium", "high", "critical"),
        default="high",
        help="Minimum risk level to consider (default: high)",
    )
    rs_parser.set_defaults(func=_cmd_audit_rubber_stamps)

    # ---- attesta trust ----
    trust_parser = subparsers.add_parser(
        "trust",
        help="Trust engine commands",
    )
    trust_parser.add_argument(
        "--store",
        dest="trust_store",
        default=None,
        metavar="PATH",
        help=f"Path to trust store (default: {_DEFAULT_TRUST_PATH})",
    )
    trust_sub = trust_parser.add_subparsers(dest="trust_command", metavar="<subcommand>")

    # attesta trust show <agent_id>
    show_parser = trust_sub.add_parser(
        "show",
        help="Show trust profile for an agent",
    )
    show_parser.add_argument("agent_id", help="The agent identifier")
    show_parser.set_defaults(func=_cmd_trust_show)

    # attesta trust list
    list_parser = trust_sub.add_parser(
        "list",
        help="List all known agents and their trust scores",
    )
    list_parser.set_defaults(func=_cmd_trust_list)

    # attesta trust revoke <agent_id>
    revoke_parser = trust_sub.add_parser(
        "revoke",
        help="Revoke trust for an agent",
    )
    revoke_parser.add_argument("agent_id", help="The agent identifier")
    revoke_parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip confirmation prompt",
    )
    revoke_parser.set_defaults(func=_cmd_trust_revoke)

    # ---- attesta mcp ----
    mcp_parser = subparsers.add_parser(
        "mcp",
        help="MCP server integration commands",
    )
    mcp_sub = mcp_parser.add_subparsers(dest="mcp_command", metavar="<subcommand>")

    # attesta mcp wrap -- <command> [args...]
    mcp_wrap_parser = mcp_sub.add_parser(
        "wrap",
        help="Wrap any MCP server with Attesta approval",
        description=(
            "Start a stdio proxy between the MCP client and an upstream "
            "MCP server.  Every tools/call request is evaluated by Attesta "
            "before being forwarded.  Denied calls never reach the upstream "
            "server."
        ),
    )
    mcp_wrap_parser.add_argument(
        "--config", "-c",
        default=None,
        metavar="PATH",
        help=f"Path to attesta.yaml (default: {_DEFAULT_CONFIG_NAME})",
    )
    mcp_wrap_parser.add_argument(
        "--risk-override",
        action="append",
        metavar="TOOL=LEVEL",
        help="Override risk level for a tool (e.g. --risk-override rm_rf=critical)",
    )
    mcp_wrap_parser.add_argument(
        "upstream_command",
        nargs=argparse.REMAINDER,
        help="The MCP server command to wrap (after --)",
    )
    mcp_wrap_parser.set_defaults(func=_cmd_mcp_wrap)

    # ---- attesta version ----
    version_parser = subparsers.add_parser(
        "version",
        help="Print the attesta version",
    )
    version_parser.set_defaults(func=_cmd_version)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    """CLI entry point invoked by the ``attesta`` console script."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Propagate parent flags to child namespace for audit / trust sub-parsers.
    # argparse does not do this automatically for nested subparsers.
    if args.command == "audit" and hasattr(args, "audit_log") and args.audit_log:
        pass  # already on args via the parent parser
    if args.command == "trust" and hasattr(args, "trust_store") and args.trust_store:
        pass  # already on args via the parent parser

    if not hasattr(args, "func"):
        # No subcommand was given -- print help.
        if args.command == "audit":
            parser.parse_args(["audit", "--help"])
        elif args.command == "trust":
            parser.parse_args(["trust", "--help"])
        elif args.command == "mcp":
            parser.parse_args(["mcp", "--help"])
        else:
            parser.print_help()
        sys.exit(0)

    try:
        args.func(args)
    except KeyboardInterrupt:
        print()
        sys.exit(130)
    except Exception as exc:
        _err(str(exc))


if __name__ == "__main__":
    main()
