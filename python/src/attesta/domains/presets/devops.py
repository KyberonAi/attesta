"""DevOps domain profile for attesta-ai (OSS preset).

A heuristic-only domain profile covering common DevOps operations:
destructive commands, production access, permission changes, and
CI/CD pipeline modifications.  No LLM or regulated-compliance
dependencies -- purely pattern-based risk scoring.

Usage::

    from attesta.domains.presets.devops import DEVOPS_PROFILE

    # Or via the convenience loader:
    from attesta.domains.presets import load_preset
    profile = load_preset("devops")
"""

from __future__ import annotations

from attesta.domains.profile import (
    DomainChallengeTemplate,
    DomainProfile,
    EscalationRule,
    RiskPattern,
    registry,
)

# ---------------------------------------------------------------------------
# Risk patterns
# ---------------------------------------------------------------------------

_DEVOPS_RISK_PATTERNS: list[RiskPattern] = [
    # -- Destructive file-system operations --
    RiskPattern(
        pattern=r"\brm\s+(?:-\w*\s+)*-r|\brm\s+-rf\b|\brmdir\b",
        target="any",
        risk_contribution=0.90,
        name="recursive_delete",
        description=(
            "Recursive file deletion (rm -rf) can permanently destroy "
            "directory trees with no recovery path unless backups exist."
        ),
    ),

    # -- Kubernetes destructive operations --
    RiskPattern(
        pattern=r"\bkubectl\s+delete\b|\bkubectl_delete\b",
        target="any",
        risk_contribution=0.85,
        name="kubectl_delete",
        description=(
            "kubectl delete removes Kubernetes resources from the cluster. "
            "Deleting stateful workloads or namespaces may cause data loss."
        ),
    ),

    # -- Terraform destroy --
    RiskPattern(
        pattern=r"\bterraform\s+destroy\b|\btf_destroy\b|\bterraform_destroy\b",
        target="any",
        risk_contribution=0.95,
        name="terraform_destroy",
        description=(
            "terraform destroy tears down all managed infrastructure. "
            "This is an irreversible operation that can remove databases, "
            "networks, and compute resources in a single command."
        ),
    ),

    # -- Docker container removal --
    RiskPattern(
        pattern=r"\bdocker\s+rm\b|\bdocker_rm\b|\bdocker\s+(?:image\s+)?rmi\b",
        target="any",
        risk_contribution=0.60,
        name="docker_remove",
        description=(
            "docker rm / rmi removes containers or images. Running "
            "containers with unsaved state will lose their data."
        ),
    ),

    # -- SQL destructive operations --
    RiskPattern(
        pattern=r"\bDROP\s+TABLE\b|\bdrop_table\b",
        target="any",
        risk_contribution=0.95,
        name="sql_drop_table",
        description=(
            "DROP TABLE permanently removes a database table and all "
            "its data. This cannot be undone without a backup restore."
        ),
    ),
    RiskPattern(
        pattern=r"\bTRUNCATE\s+(?:TABLE\s+)?\b|\btruncate_table\b",
        target="any",
        risk_contribution=0.90,
        name="sql_truncate",
        description=(
            "TRUNCATE removes all rows from a table. Unlike DELETE, "
            "it typically cannot be rolled back and skips row-level triggers."
        ),
    ),

    # -- Production access patterns --
    RiskPattern(
        pattern=(
            r"\bprod(?:uction)?[_\-.]?db\b"
            r"|\bconnect[_\-]prod\b"
            r"|\bprod[_\-]connection\b"
        ),
        target="any",
        risk_contribution=0.80,
        name="production_db_access",
        description=(
            "Direct production database access bypasses application "
            "safeguards and audit logging. Queries run here affect "
            "live customer data."
        ),
    ),
    RiskPattern(
        pattern=(
            r"\bdeploy[_\-](?:to[_\-])?prod(?:uction)?\b"
            r"|\bprod[_\-]deploy\b"
            r"|\brelease[_\-](?:to[_\-])?prod\b"
        ),
        target="any",
        risk_contribution=0.80,
        name="prod_deployment",
        description=(
            "Production deployments directly affect end-user experience "
            "and service availability. They should follow change-management "
            "procedures."
        ),
    ),
    RiskPattern(
        pattern=(
            r"\bupdate[_\-]dns\b"
            r"|\bmodify[_\-]dns\b"
            r"|\bdns[_\-]change\b"
            r"|\bchange[_\-]nameserver\b"
        ),
        target="any",
        risk_contribution=0.75,
        name="dns_change",
        description=(
            "DNS changes affect service routing globally. Misconfigurations "
            "propagate slowly and are difficult to roll back quickly."
        ),
    ),

    # -- Permission changes --
    RiskPattern(
        pattern=r"\bchmod\b|\bchmod_recursive\b",
        target="any",
        risk_contribution=0.70,
        name="chmod_change",
        description=(
            "chmod alters file permissions. Overly permissive changes "
            "(e.g. 777) can expose sensitive files to unauthorized users."
        ),
    ),
    RiskPattern(
        pattern=r"\bchown\b|\bchown_recursive\b",
        target="any",
        risk_contribution=0.70,
        name="chown_change",
        description=(
            "chown changes file ownership. Transferring ownership of "
            "system files can break services or escalate privileges."
        ),
    ),
    RiskPattern(
        pattern=(
            r"\bfirewall[_\-]rule\b"
            r"|\biptables\b"
            r"|\bufw\b"
            r"|\bmodify[_\-]firewall\b"
        ),
        target="any",
        risk_contribution=0.85,
        name="firewall_rule_change",
        description=(
            "Firewall rule changes modify the network security perimeter. "
            "Incorrect rules may expose internal services or block "
            "legitimate traffic."
        ),
    ),

    # -- CI/CD pipeline modifications --
    RiskPattern(
        pattern=(
            r"\bpipeline[_\-](?:update|modify|delete|create)\b"
            r"|\bci[_\-]config\b"
            r"|\bgithub[_\-]action\b"
            r"|\b\.github/workflows\b"
        ),
        target="any",
        risk_contribution=0.65,
        name="cicd_pipeline_change",
        description=(
            "CI/CD pipeline modifications change build, test, and deployment "
            "automation. Malicious changes could inject code or disable "
            "security checks in the delivery process."
        ),
    ),
    RiskPattern(
        pattern=(
            r"\bJenkinsfile\b"
            r"|\b\.gitlab-ci\.yml\b"
            r"|\bbuildspec\.yml\b"
        ),
        target="any",
        risk_contribution=0.60,
        name="cicd_config_file",
        description=(
            "Modifications to CI/CD configuration files (Jenkinsfile, "
            "GitLab CI, CodeBuild) affect the entire delivery pipeline."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Escalation rules
# ---------------------------------------------------------------------------

_DEVOPS_ESCALATION_RULES: list[EscalationRule] = [
    EscalationRule(
        condition="risk_score >= 0.9",
        action="require_multi_party",
        required_approvers=2,
        notify_roles=["ops_lead", "on_call_engineer"],
        description=(
            "Very high risk DevOps operations require approval from "
            "both the ops lead and on-call engineer before proceeding."
        ),
    ),
    EscalationRule(
        condition="matches_pattern:terraform_destroy",
        action="block",
        required_approvers=1,
        notify_roles=["infra_lead"],
        description=(
            "terraform destroy is blocked by default. It must be "
            "authorized through an explicit infrastructure change request."
        ),
    ),
    EscalationRule(
        condition="matches_pattern:firewall_rule_change",
        action="require_teach_back",
        required_approvers=1,
        notify_roles=["security_team"],
        description=(
            "Firewall rule changes require the operator to explain "
            "the intended effect and confirm no services are exposed."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Challenge templates
# ---------------------------------------------------------------------------

_DEVOPS_CHALLENGE_TEMPLATES: list[DomainChallengeTemplate] = [
    DomainChallengeTemplate(
        question_template=(
            "What is the rollback plan if '{function_name}' fails or "
            "causes an incident?"
        ),
        answer_hints=[
            "rollback", "revert", "backup", "restore",
            "previous version", "undo",
        ],
        context_vars=["function_name"],
        challenge_type="teach_back",
        min_risk_level="high",
    ),
    DomainChallengeTemplate(
        question_template=(
            "Which environment is targeted by '{function_name}'? "
            "Please confirm."
        ),
        answer_hints=[
            "production", "staging", "development", "sandbox",
        ],
        context_vars=["function_name"],
        challenge_type="quiz",
        min_risk_level="medium",
    ),
    DomainChallengeTemplate(
        question_template=(
            "Have the changes behind '{function_name}' been tested in "
            "a non-production environment?"
        ),
        answer_hints=[
            "yes", "staging", "tested", "passed",
            "verified", "smoke test",
        ],
        context_vars=["function_name"],
        challenge_type="quiz",
        min_risk_level="high",
    ),
]


# ---------------------------------------------------------------------------
# Profile definition
# ---------------------------------------------------------------------------

DEVOPS_PROFILE = DomainProfile(
    name="devops",
    display_name="DevOps",
    description=(
        "Heuristic-only domain profile for DevOps and operations teams. "
        "Covers destructive commands (rm -rf, kubectl delete, terraform "
        "destroy, DROP TABLE, TRUNCATE), production access (database "
        "connections, deployments, DNS changes), permission changes "
        "(chmod, chown, firewall rules), and CI/CD pipeline modifications. "
        "No LLM or regulated-compliance dependencies."
    ),
    risk_patterns=_DEVOPS_RISK_PATTERNS,
    sensitive_terms={
        "production": 0.7,
        "destroy": 0.9,
        "delete": 0.6,
        "drop": 0.8,
        "truncate": 0.8,
        "root": 0.8,
        "sudo": 0.9,
        "admin": 0.7,
        "firewall": 0.7,
        "secret": 0.8,
        "credential": 0.8,
    },
    critical_actions=[
        "terraform_destroy",
        "drop_database",
        "drop_table",
        "delete_namespace",
        "rm_rf",
    ],
    safe_actions=[
        "get_status",
        "list_pods",
        "describe_service",
        "view_logs",
        "get_metrics",
        "check_health",
        "kubectl_get",
        "terraform_plan",
    ],
    escalation_rules=_DEVOPS_ESCALATION_RULES,
    challenge_templates=_DEVOPS_CHALLENGE_TEMPLATES,
    min_review_overrides={
        "critical": 30.0,
        "high": 10.0,
    },
    base_risk_floor=0.05,
    production_multiplier=1.4,
    required_vocabulary=[
        "rollback",
        "downtime",
        "deployment",
        "backup",
        "monitoring",
    ],
)


# ---------------------------------------------------------------------------
# Auto-register with the global registry
# ---------------------------------------------------------------------------

if DEVOPS_PROFILE.name not in registry:
    registry.register(DEVOPS_PROFILE)
