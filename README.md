<p align="center">
  <strong>attesta</strong><br>
  <em>Advanced Human-in-the-Loop for Agentic AI</em>
</p>

<p align="center">
  <a href="https://pypi.org/project/attesta/"><img alt="PyPI" src="https://img.shields.io/pypi/v/attesta?color=blue"></a>
  <a href="https://pypi.org/project/attesta/"><img alt="Python" src="https://img.shields.io/pypi/pyversions/attesta"></a>
  <a href="./LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-green"></a>
  <a href="./.github/workflows/ci.yaml"><img alt="CI" src="https://img.shields.io/badge/ci-configured-blue"></a>
  <img alt="Status" src="https://img.shields.io/badge/status-early%20release-orange">
</p>

---

> **Early Release (v0.1.x)** — Attesta is under active development. The core API (`@gate`, risk scoring, challenges, audit trail) is functional and tested, but interfaces may change between minor versions. Pin your dependency to a specific version in production. Feedback and contributions are welcome!

---

Your AI agent asks to delete a production database. A dialog pops up: **"Approve? [Y/n]"**. You hit `y` without reading. Sound familiar?

This is the **rubber-stamping problem**. Every human-in-the-loop system suffers from it. Approval fatigue sets in, operators click "yes" reflexively, and the one time they should have said "no," they don't.

**Attesta** fixes this. Instead of a single yes/no prompt for everything, it scores the risk of every action and selects a verification challenge calibrated to that risk -- from auto-approving safe reads to requiring multi-party sign-off with teach-back verification for irreversible operations.

The result: low-risk actions flow through without friction. High-risk actions *demand proof that you understood what you just approved*.

## Project Structure

```
attesta/
  python/          # Python SDK (PyPI: attesta)
    src/attesta/   # Source code
    tests/         # Test suite
    pyproject.toml # Package config
  typescript/      # TypeScript SDK (npm: @kyberon/attesta)
    src/           # Source code
    package.json   # Package config
    tsconfig.json  # TS config
  README.md        # This file
  LICENSE
```

## Quick Start

Two lines. No configuration needed.

```python
from attesta import gate

@gate
def deploy(service: str, version: str):
    """Deploy a service to production."""
    ...
```

That is it. When `deploy()` is called, attesta automatically:

1. **Scores the risk** using 5 factors (function name, arguments, docstring, hints, novelty)
2. **Selects a challenge** proportional to that risk
3. **Presents the challenge** to the operator
4. **Logs the decision** to a tamper-proof audit trail

> **Note:** Python `@gate` auto-detects the environment. In an interactive terminal it shows rich prompts (`pip install attesta[terminal]`). In CI/headless or without `rich` installed, Python falls back to auto-approve. In TypeScript, non-interactive mode defaults to deny unless you configure a renderer explicitly. For full control over rendering and audit, use the [Recommended Setup](#recommended-setup) below.

### Install

**Python** (from `python/` subdirectory):

```bash
cd python
pip install -e "."
```

Or from PyPI:

```bash
pip install attesta
```

The core library has **zero dependencies**. Add what you need:

```bash
pip install attesta[terminal]    # Rich terminal UI
pip install attesta[yaml]        # YAML config support
pip install attesta[langchain]   # LangChain/LangGraph integration
pip install attesta[openai]      # OpenAI Agents SDK integration
pip install attesta[anthropic]   # Anthropic Claude integration
pip install attesta[crewai]      # CrewAI integration
pip install attesta[all]         # Rich terminal UI + YAML config support
```

Requires Python 3.11+.

**TypeScript** (from `typescript/` subdirectory):

```bash
cd typescript
npm install
npm run build
```

## Recommended Setup

For teams and production use, start with a config file, terminal renderer, and audit logging:

1. Create `attesta.yaml`:
```yaml
policy:
  minimum_review_seconds:
    low: 0
    medium: 3
    high: 10
    critical: 30
  require_multi_party:
    critical: 2
  fail_mode: deny

trust:
  initial_score: 0.3
  decay_rate: 0.01

audit:
  path: ".attesta/audit.jsonl"
```

2. Initialize attesta:
```python
from attesta import Attesta
from attesta.renderers import TerminalRenderer
from attesta.core.audit import AuditLogger

attesta = Attesta.from_config("attesta.yaml")

@attesta.gate(risk_hints={"production": True})
def deploy(service: str, version: str):
    ...
```

This gives you:
- Interactive terminal prompts (not silent auto-approve)
- Risk-calibrated challenges loaded from config
- Persistent audit trail
- Adaptive trust that lets agents earn autonomy

## How It Works

Every gated action passes through a four-stage pipeline:

```
  Action called
       |
  [1. Risk Scoring]    -- Analyze function name, args, docstring, hints, novelty
       |
  [2. Challenge Selection]  -- Map risk level to verification challenge
       |
  [3. Verification]    -- Present challenge, collect response, validate
       |
  [4. Audit]           -- Log decision to hash-chained JSONL
       |
  Execute or Deny
```

### Risk Levels and Default Challenges

| Risk Score | Level      | Default Challenge | What Happens                                   |
|-----------|------------|-------------------|------------------------------------------------|
| 0.0 - 0.3 | **LOW**    | Auto-approve      | Action executes silently                        |
| 0.3 - 0.6 | **MEDIUM** | Confirm           | Y/N prompt with action summary                  |
| 0.6 - 0.8 | **HIGH**   | Quiz              | Comprehension questions about the action         |
| 0.8 - 1.0 | **CRITICAL** | Multi-party     | 2+ independent approvers, each with their own challenge |

## Challenge Types

### Confirm

Simple Y/N with enforced minimum review time. The operator must wait before the prompt becomes active -- no speed-clicking.

```python
@gate(risk="medium")
def update_config(key: str, value: str):
    ...
```

### Quiz

Auto-generates 1-3 comprehension questions from the action's actual parameters. "What directory will be affected?" "Which database table will be modified?" The operator must answer correctly to proceed.

```python
@gate(risk="high")
def drop_table(table_name: str, database: str):
    """Irreversibly drops a database table."""
    ...
```

### Teach-Back

The strongest single-person challenge. The operator must explain, in their own words, what the action will do and what its effects are. Validated against key terms from the action context. Optionally validated by an LLM for comprehension quality.

```python
from attesta.challenges.teach_back import TeachBackChallenge

challenge = TeachBackChallenge(min_words=15, min_review_seconds=30)
```

### Multi-Party

Requires 2+ independent human approvers, each assigned a different sub-challenge. The first approver gets the hardest challenge (teach-back), the second gets a quiz, and so on. All must pass. One denial stops everything.

```python
from attesta.challenges.multi_party import MultiPartyChallenge

challenge = MultiPartyChallenge(required_approvers=3)
```

> **Note:** Multi-party approval in the default terminal renderer collects approvals sequentially (one operator at a time at the same terminal). For production multi-party workflows with parallel approval collection (e.g., via Slack, email, or web UI), subclass `MultiPartyChallenge` and override the `_collect_approval()` method to implement your routing and identity verification. See `challenges/multi_party.py` for the extension point.

## Risk Scoring

### Automatic Detection

The built-in `DefaultRiskScorer` analyzes five factors with weighted contributions:

| Factor | Weight | Signal |
|--------|--------|--------|
| **Function name** | 30% | `delete_*`, `deploy`, `send_*` score higher than `read_*`, `get_*` |
| **Arguments** | 25% | Detects SQL (`DROP`, `DELETE`), shell commands (`rm -rf`, `sudo`), secrets, PII patterns |
| **Docstring** | 20% | Keywords like "irreversible", "destructive", "production", "dangerous" |
| **Hints** | 15% | Caller-supplied metadata: `{"production": True, "pii": True}` |
| **Novelty** | 10% | First-time actions score 0.9; frequently seen actions score 0.1 |

### Custom Risk Scorers

Implement the `RiskScorer` protocol -- just a `score(ctx)` method and a `name` property:

```python
class ComplianceScorer:
    @property
    def name(self) -> str:
        return "compliance"

    def score(self, ctx):
        if "pii" in str(ctx.kwargs).lower():
            return 0.9
        if ctx.environment == "production":
            return 0.6
        return 0.2
```

### Composing Scorers

Combine multiple scorers with weighted averaging or take the maximum (most conservative):

```python
from attesta.core.risk import CompositeRiskScorer, MaxRiskScorer, DefaultRiskScorer

# Weighted average
scorer = CompositeRiskScorer([
    (DefaultRiskScorer(), 0.7),
    (ComplianceScorer(), 0.3),
])

# Most conservative signal wins
scorer = MaxRiskScorer([DefaultRiskScorer(), ComplianceScorer()])
```

### Risk Hints

Pass runtime context to influence scoring without writing a custom scorer:

```python
@gate(risk_hints={"production": True, "destructive": True, "pii": True})
def wipe_user_data(user_id: str):
    ...
```

## Domain Profiles

Out of the box, `DefaultRiskScorer` is domain-agnostic — it flags `delete_*` and `rm -rf` but knows nothing about your industry's compliance requirements. Domain profiles fix this by encoding industry-specific risk patterns, compliance references, escalation rules, and challenge templates.

### Register a custom domain profile

```python
from attesta.domains.profile import DomainProfile, RiskPattern
from attesta.domains.presets import register_preset

my_profile = DomainProfile(
    name="my-domain",
    display_name="My Domain",
    description="Custom domain profile for my organization.",
    risk_patterns=[
        RiskPattern(
            pattern=r"delete_.*|drop_.*",
            target="function_name",
            risk_contribution=0.85,
            name="destructive_ops",
            description="Destructive operations",
        ),
    ],
    sensitive_terms={"secret": 0.9, "credentials": 0.85},
    critical_actions=["delete_database", "revoke_access"],
    safe_actions=["get_status", "list_items"],
    base_risk_floor=0.15,
    production_multiplier=1.5,
)

# Register so it can be activated via YAML config
register_preset(my_profile, aliases=["my-alias"])
```

Then activate in config:

```yaml
# attesta.yaml
domain: my-domain
```

### What a domain profile contains

```python
profile.risk_patterns        # Regex patterns that match risky function signatures
profile.sensitive_terms      # {"term": weight} — terms in args/docs that amplify risk
profile.critical_actions     # Actions that floor risk to 0.8+ regardless of scorer
profile.safe_actions         # Actions that cap risk at 0.15 regardless of scorer
profile.escalation_rules     # Conditional rules (e.g., bulk ops → 3-party approval)
profile.challenge_templates  # Domain-specific quiz/teach-back question templates
profile.compliance_frameworks  # Referenced frameworks (for audit trail)
profile.production_multiplier  # Risk multiplier for production environment
profile.base_risk_floor      # Minimum risk score for all actions in this domain
```

### Combining domains

For systems that span multiple custom profiles:

```yaml
# attesta.yaml
domain: [profile-a, profile-b]
```

Profiles are merged: all risk patterns, sensitive terms, escalation rules, and challenge templates from both custom profiles are combined. For conflicting scalar values (risk floor, production multiplier), the most conservative value wins.

### Custom domain profiles

```python
from attesta.domains import DomainProfile, DomainRiskScorer, RiskPattern

my_domain = DomainProfile(
    name="ecommerce",
    display_name="E-Commerce",
    description="Risk profile for e-commerce platforms.",
    risk_patterns=[
        RiskPattern(
            pattern=r"\brefund\b|\bchargeback\b",
            target="function_name",
            risk_contribution=0.7,
            name="refund_operation",
            description="Refund/chargeback operations carry fraud risk.",
        ),
    ],
    sensitive_terms={"credit_card": 0.95, "shipping_address": 0.6},
    critical_actions=["bulk_refund", "delete_customer_data"],
    safe_actions=["get_product", "list_categories"],
    production_multiplier=1.5,
)

attesta = Attesta(risk_scorer=DomainRiskScorer(my_domain))
```

### Escalation rules in action

A custom domain profile can define escalation rules that trigger special handling beyond the standard challenge ladder:

```
Action: bulk_export(format="csv", record_count=50000)

→ Pattern match: bulk_export_data (risk: 0.90)
→ Escalation rule fires: "require_multi_party"
  - Required approvers: 3
  - Notified roles: compliance_officer, team_lead, department_head
  - Reason: "Bulk export operations require three-party approval"

→ Instead of a simple "Approve? [y/n]", three separate reviewers must
  each independently pass their own challenge before the action proceeds.
```

Escalation rules can also block certain actions entirely:

```
Action: override_security_alert(alert_id="ALERT-2024-001")

→ Pattern match: security_override (risk: 0.90)
→ Escalation rule fires: "block"
  - Notified roles: security_officer, compliance_officer, team_lead
  - Reason: "Security alert overrides are blocked. Requires out-of-band review."

→ The action is denied automatically. No amount of approval can override it
  through the normal flow — it requires formal out-of-band procedures.
```

## Adaptive Trust

Agents earn autonomy over time. The `TrustEngine` uses a Bayesian-inspired model that combines three signals:

- **Weighted success rate** -- recent actions matter more (exponential decay)
- **Recency factor** -- trust decays during inactivity
- **Incident penalty** -- each security incident multiplicatively reduces trust

```python
from attesta.core.trust import TrustEngine
from pathlib import Path

trust = TrustEngine(
    initial_score=0.3,    # Start cautious
    ceiling=0.9,          # Trust never reaches 1.0
    decay_rate=0.01,      # Per-day decay
    incident_penalty=0.7, # Multiply by this per incident
    influence=0.3,        # Max risk reduction from trust
    storage_path=Path(".attesta/trust.json"),
)

# Record outcomes -- trust adjusts automatically
trust.record_success("agent-47", "deploy", domain="infrastructure")
trust.record_denial("agent-47", "drop_database", domain="data")

# Trust modifies effective risk
raw_risk = 0.7
adjusted = trust.effective_risk(raw_risk, "agent-47", domain="infrastructure")
# A trusted agent sees lower effective risk; an untrusted one sees higher

# Instant revocation for security incidents
trust.revoke("compromised-agent")
```

Trust never fully bypasses CRITICAL actions and is capped below 1.0 as a safety ceiling.

## Tamper-Proof Audit

Every decision is recorded in a **hash-chained JSONL** audit log. Each entry's `chain_hash` is the SHA-256 digest of the previous entry's hash concatenated with the current entry's canonical JSON. Tampering with any entry breaks the chain.

```python
from attesta.core.audit import AuditLogger

audit = AuditLogger(path=".attesta/audit.jsonl")

# Verify the entire chain
intact, total, broken_indices = audit.verify_chain()
print(f"Chain intact: {intact} ({total} entries)")

# Query entries
critical_denials = audit.query(risk_level="critical", verdict="denied")

# Detect rubber-stamping: fast approvals on high-risk actions
stamps = audit.find_rubber_stamps(max_review_seconds=5.0, min_risk="high")
print(f"Found {len(stamps)} suspicious rubber-stamps")
```

## Framework Integrations

### LangChain / LangGraph

```python
from attesta import Attesta
from attesta.integrations import AttestaToolWrapper, attesta_node

attesta = Attesta()

# Wrap all tools
wrapper = AttestaToolWrapper(attesta, risk_overrides={"delete_db": "critical"})
protected_tools = wrapper.wrap_tools(tools)

# Or use as a LangGraph node
node = attesta_node(attesta)
```

```bash
pip install attesta[langchain]
```

#### Real-World Example: AI Agent with LangGraph

An AI assistant with domain-aware approval that treats each action differently based on risk.

**1. Config** — `attesta.yaml`:

```yaml
# domain: my-domain  # Activate a registered domain profile (optional)

policy:
  minimum_review_seconds:
    medium: 3
    high: 10
    critical: 30
  fail_mode: deny

trust:
  influence: 0.3
  ceiling: 0.9

audit:
  path: ".attesta/audit.jsonl"
```

**2. Define the tools:**

```python
from langchain_core.tools import tool

@tool
def check_status(service: str) -> dict:
    """Check the health and status of a deployed service."""
    return ops.get_service_status(service)

@tool
def deploy_service(service: str, version: str, environment: str) -> dict:
    """Deploy a service to the specified environment."""
    return ops.deploy(service, version, environment)

@tool
def restart_service(service: str, environment: str) -> dict:
    """Restart a running service. Causes brief downtime."""
    return ops.restart(service, environment)

@tool
def rollback_service(service: str, target_version: str) -> dict:
    """Roll back a service to a previous version. Requires justification."""
    return ops.rollback(service, target_version)

@tool
def delete_database(database: str, environment: str) -> str:
    """Irreversibly delete a database and all its data."""
    return ops.drop_database(database, environment)
```

**3. Build the LangGraph agent:**

```python
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, MessagesState
from langgraph.prebuilt import ToolNode

from attesta import Attesta
from attesta.integrations.langchain import attesta_node

# Load config
attesta = Attesta.from_config("attesta.yaml")

tools = [check_status, deploy_service, restart_service,
         rollback_service, delete_database]

llm = ChatOpenAI(model="gpt-4o").bind_tools(tools)

def agent(state: MessagesState):
    return {"messages": [llm.invoke(state["messages"])]}

def should_continue(state: MessagesState):
    last = state["messages"][-1]
    if hasattr(last, "tool_calls") and last.tool_calls:
        return "approval"
    return "end"

# Build the graph
graph = StateGraph(MessagesState)
graph.add_node("agent", agent)
graph.add_node("approval", attesta_node(attesta))  # <-- Attesta sits here
graph.add_node("tools", ToolNode(tools))

graph.set_entry_point("agent")
graph.add_conditional_edges("agent", should_continue, {"approval": "approval", "end": "__end__"})
graph.add_edge("approval", "tools")
graph.add_edge("tools", "agent")

app = graph.compile()
```

**4. What happens for each tool call:**

| Tool Call | Risk Behavior | Risk | Challenge |
|---|---|---|---|
| `check_status("api")` | Read-only status check → score stays low | **LOW** (0.08) | Auto-approve |
| `deploy_service("api", "2.1.0", "staging")` | `deploy` in function name + staging environment | **MEDIUM** (0.45) | Confirm: "Deploy api v2.1.0 to staging?" |
| `restart_service("api", "production")` | `restart` keyword + production environment → risk amplified | **HIGH** (0.72) | Quiz: "Which service and environment?" |
| `rollback_service("api", "2.0.0")` | Rollback operation + escalation rule fires → teach-back | **CRITICAL** (0.85) | Teach-back: "Explain why this rollback is needed" |
| `delete_database("users-db", "production")` | `delete` + `database` + production → maximum risk | **CRITICAL** (0.95) | Multi-party: 3 approvers (ops + team lead + dept head) |

The agent flows naturally -- checking service status is instant, but the moment it tries to restart a production service or delete a database, the risk scoring kicks in with appropriately calibrated verification. The audit log records every decision with compliance references for regulatory review.

**5. Run it:**

```python
import asyncio

result = asyncio.run(app.ainvoke({
    "messages": [("user", "Check the API service status and then deploy version 2.1.0 to production")]
}))
```

The agent will call `check_status` (auto-approved) and then `deploy_service` (confirm challenge). If either is denied, the denied tool call is stripped from the message and the agent gets a denial message instead -- it can inform the user without executing the action.

### OpenAI Agents SDK

```python
from openai.agents import Agent, Runner
from attesta.integrations import attesta_approval_handler, AttestaGuardrail

attesta = Attesta()

# As a Runner-level approval handler
result = await Runner.run(
    agent,
    input="Deploy to production",
    approval_handler=attesta_approval_handler(attesta),
)

# Or as a per-agent guardrail
agent = Agent(
    name="deploy-bot",
    tool_guardrails=[AttestaGuardrail(attesta)],
)
```

```bash
pip install attesta[openai]
```

### CrewAI

```python
from crewai import Task
from attesta.integrations import AttestaHumanInput

attesta_input = AttestaHumanInput(attesta, default_risk="high")
task = Task(
    description="Deploy service to production",
    human_input=True,
    callback=attesta_input,
)
```

```bash
pip install attesta[crewai]
```

### Anthropic Claude

```python
from anthropic import Anthropic
from attesta.integrations import AttestaToolGate

client = Anthropic()
gate = AttestaToolGate(attesta, risk_overrides={"run_bash": "critical"})

response = client.messages.create(...)
for block in response.content:
    if block.type == "tool_use":
        approved, result = await gate.evaluate_tool_use(block)
        if not approved:
            denial = gate.make_denial_result(block.id)
```

```bash
pip install attesta[anthropic]
```

### MCP (Model Context Protocol)

MCP servers power tool use in VS Code Copilot, Cursor, Claude Code, Windsurf, and other AI-enabled editors. Attesta provides two ways to enforce HITL approval on MCP tool calls.

#### Option 1: Proxy (zero code changes, any MCP server)

Wrap any existing MCP server with the Attesta proxy. No code changes required — just change the command in your editor's MCP config:

**Before** (unprotected):
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

**After** (protected by Attesta):
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "attesta",
      "args": ["mcp", "wrap", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

The proxy sits between the editor and the real MCP server:

```
Editor / IDE  ←stdio→  Attesta Proxy  ←stdio→  Real MCP Server
                            |
                            ├── Risk scoring per tool call
                            ├── Domain-aware evaluation
                            ├── Policy enforcement
                            └── Tamper-proof audit trail
```

Every `tools/call` request is intercepted and evaluated. Low-risk calls pass through transparently. High-risk calls are denied and the AI receives an error message explaining why. The audit log captures every decision.

```bash
# With risk overrides for specific tools
attesta mcp wrap --risk-override write_file=high --risk-override execute_command=critical \
  -- npx @modelcontextprotocol/server-filesystem /home/user
```

#### Option 2: Decorator (for Python MCP servers)

If you author your own MCP servers in Python, use the decorator directly:

```python
from mcp.server import Server
from attesta import Attesta
from attesta.integrations.mcp import attesta_tool_handler

server = Server("my-server")
attesta = Attesta.from_config("attesta.yaml")

@server.call_tool()
@attesta_tool_handler(attesta, risk_overrides={"drop_table": "critical"})
async def call_tool(name: str, arguments: dict):
    # Only executes if Attesta approves
    ...
```

#### Enterprise deployment

For company-wide MCP governance:

1. Create a shared `attesta.yaml` with domain profiles and policies:
```yaml
# domain: my-domain  # Optional: activate a registered domain profile
policy:
  fail_mode: deny
  timeout_seconds: 300
risk:
  overrides:
    execute_command: critical
    write_file: high
audit:
  path: "/var/log/attesta/mcp-audit.jsonl"
```

2. Distribute the config and wrap all MCP servers via a company-standard editor config:
```json
{
  "mcpServers": {
    "database": {
      "command": "attesta",
      "args": ["mcp", "wrap", "-c", "/etc/attesta/attesta.yaml",
               "--", "npx", "mcp-server-postgres", "postgresql://..."]
    },
    "github": {
      "command": "attesta",
      "args": ["mcp", "wrap", "-c", "/etc/attesta/attesta.yaml",
               "--", "npx", "@modelcontextprotocol/server-github"]
    }
  }
}
```

3. All tool calls across all developers and all MCP servers are now:
   - Risk-scored using domain-aware profiles
   - Enforced by policy (auto-approve safe reads, deny critical mutations)
   - Logged to a central audit trail for compliance review

```bash
pip install attesta
```

MCP support is included in the core package — no additional extras required.

## Configuration

### Programmatic

```python
from attesta import Attesta
from attesta.core.types import RiskLevel, ChallengeType

attesta = Attesta(
    policy={
        "default_environment": "production",
        "min_review_seconds": 2.0,
        "challenge_map": {
            "low": "auto_approve",
            "medium": "confirm",
            "high": "quiz",
            "critical": "multi_party",
        },
    },
)

@attesta.gate(risk_hints={"production": True})
def deploy(service: str, version: str):
    ...
```

### YAML Config

```bash
cp attesta.yaml.example attesta.yaml
```

```yaml
# attesta.yaml

# Domain profile for industry-specific risk scoring (optional).
# Register custom profiles with register_preset(), then activate here.
# domain: my-domain

policy:
  minimum_review_seconds:
    low: 0
    medium: 3
    high: 10
    critical: 30
  require_multi_party:
    critical: 2
  fail_mode: deny
  timeout_seconds: 300

risk:
  overrides:
    deploy_production: critical
    restart_service: high

trust:
  influence: 0.3
  ceiling: 0.9
  initial_score: 0.3
  decay_rate: 0.01

audit:
  path: ".attesta/audit.jsonl"
```

```python
attesta = Attesta.from_config("attesta.yaml")
```

### The `@gate` Decorator

The decorator supports three calling styles and extensive customization:

```python
@gate                                        # bare -- auto-detect everything
@gate()                                      # empty parens -- same as bare
@gate(                                       # fully configured
    risk="high",                             # explicit risk override
    risk_hints={"pii": True},               # hints for the scorer
    risk_scorer=my_scorer,                   # custom scorer
    renderer=TerminalRenderer(),             # custom UI
    audit_logger=AuditLogger("audit.jsonl"), # custom audit backend
    min_review_seconds=5.0,                  # anti-rubber-stamp timer
    environment="production",                # environment tag
    agent_id="agent-47",                     # agent tracking
    session_id="sess-abc",                   # session tracking
)
def dangerous_operation():
    ...
```

Works on both sync and async functions. Raises `AttestaDenied` when the operator denies the action.

## CLI Reference

The **`attesta`** CLI is installed automatically with the Python package:

```bash
# Initialize attesta in your project
attesta init

# Verify audit chain integrity
attesta audit verify
attesta audit verify --path .attesta/audit.jsonl

# Show audit statistics
attesta audit stats --risk-level critical

# Export audit entries
attesta audit export --from 2025-01-01 --to 2025-06-01

# Detect rubber-stamping
attesta audit rubber-stamps --max-seconds 5

# Inspect trust profiles
attesta trust show agent-47
attesta trust list
attesta trust revoke compromised-agent
```

## TypeScript SDK

The TypeScript package (`@kyberon/attesta`) mirrors the Python API:

```typescript
import { Attesta, TerminalRenderer } from '@kyberon/attesta';

const attesta = new Attesta({
  renderer: new TerminalRenderer(),
});

const result = await attesta.evaluate({
  functionName: 'deployService',
  args: ['api', '2.0.0'],
  kwargs: {},
  hints: { production: true },
  environment: 'production',
  description: 'deployService("api", "2.0.0")',
});

if (result.verdict === 'denied') {
  throw new Error('Deployment denied');
}
```

### Framework Integrations (TypeScript)

- **LangChain.js**: `createAttestaMiddleware()` for tool-level gating
- **Vercel AI SDK**: `createAttestaMiddleware()` as AI SDK middleware

```bash
cd typescript && npm install && npm run build
```

See `typescript/src/` for the full API.

## Architecture

```
attesta/
  core/
    types.py      # Enums, data classes, protocols (zero internal deps)
    gate.py       # @gate decorator and Attesta orchestrator
    risk.py       # Default, Composite, Max, Fixed risk scorers
    trust.py      # Bayesian adaptive trust engine
    audit.py      # Hash-chained JSONL audit logger
  challenges/
    confirm.py    # Y/N with min review time
    quiz.py       # Auto-generated comprehension questions
    teach_back.py # Free-text explanation with key-term validation
    multi_party.py # 2+ independent approvers with rotating sub-challenges
  renderers/
    terminal.py   # Rich terminal UI (graceful fallback to plain text)
  integrations/
    langchain.py  # LangChain/LangGraph tool wrapper + graph node
    openai_sdk.py # OpenAI Agents SDK approval handler + guardrail
    crewai.py     # CrewAI human_input callback replacement
    anthropic.py  # Anthropic Claude tool_use gate
  config/
    loader.py     # YAML/TOML config loading into Policy objects
```

All protocols use structural sub-typing (`typing.Protocol`). Bring your own risk scorer, renderer, challenge, or audit backend -- if it matches the protocol, it works.

## Project Resources

- Feature boundary (OSS vs Cloud): `docs/oss-vs-cloud.mdx`
- Security policy and disclosure process: `SECURITY.md`
- Support and response expectations: `SUPPORT.md`
- Maintainer triage runbook: `MAINTAINERS.md`
- Example apps: `examples/`

## Contributing

Contributions are welcome. Please open an issue to discuss significant changes before submitting a PR.

```bash
git clone https://github.com/KyberonAi/attesta.git
cd attesta/python
pip install -e ".[dev]"

# Run tests
pytest tests/

# No-code package tests
PYTHONPATH=../python/src pytest ../packages/langflow-attesta/tests ../packages/dify-attesta/tests

# Type checking
mypy src/attesta

# Linting
ruff check src/

# Performance benchmark harness
cd ..
./scripts/run_benchmarks.sh
```

## License

MIT -- see [LICENSE](LICENSE) for details.
