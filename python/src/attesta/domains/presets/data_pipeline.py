"""Data Pipeline domain profile for attesta-ai (OSS preset).

A heuristic-only domain profile for data engineering and ETL/ELT
teams.  Covers data deletion, schema migrations, PII handling,
production database access, ETL job modifications, data exports,
and backup/restore operations.  No LLM or regulated-compliance
dependencies -- purely pattern-based risk scoring.

Usage::

    from attesta.domains.presets.data_pipeline import DATA_PIPELINE_PROFILE

    # Or via the convenience loader:
    from attesta.domains.presets import load_preset
    profile = load_preset("data-pipeline")
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

_DATA_PIPELINE_RISK_PATTERNS: list[RiskPattern] = [
    # -- Data deletion / truncation --
    RiskPattern(
        pattern=(
            r"\bdelete[_\-](?:records|rows|data|partition)\b"
            r"|\bpurge[_\-](?:data|records|table)\b"
        ),
        target="any",
        risk_contribution=0.85,
        name="data_deletion",
        description=(
            "Bulk data deletion removes records that may be needed for "
            "analytics, auditing, or compliance retention requirements."
        ),
    ),
    RiskPattern(
        pattern=r"\bTRUNCATE\b|\btruncate[_\-]table\b",
        target="any",
        risk_contribution=0.90,
        name="table_truncation",
        description=(
            "TRUNCATE removes all rows from a table without row-level logging. Recovery requires a full backup restore."
        ),
    ),
    RiskPattern(
        pattern=r"\bDROP\s+TABLE\b|\bdrop[_\-]table\b|\bDROP\s+DATABASE\b",
        target="any",
        risk_contribution=0.95,
        name="drop_table",
        description=(
            "DROP TABLE / DROP DATABASE permanently destroys the schema "
            "and data. This is irreversible without a backup."
        ),
    ),
    # -- Schema migration --
    RiskPattern(
        pattern=(
            r"\bALTER\s+TABLE\b"
            r"|\balter[_\-]table\b"
            r"|\balter[_\-]column\b"
        ),
        target="any",
        risk_contribution=0.70,
        name="schema_alter",
        description=(
            "ALTER TABLE changes the database schema. Column type changes, "
            "renames, or constraint modifications can break downstream "
            "consumers and pipelines."
        ),
    ),
    RiskPattern(
        pattern=(
            r"\brun[_\-]migration\b"
            r"|\bdb[_\-]migrate\b"
            r"|\bschema[_\-]migration\b"
            r"|\balembic\b"
            r"|\bflyway\b"
        ),
        target="any",
        risk_contribution=0.75,
        name="schema_migration",
        description=(
            "Schema migrations modify the database structure. They may "
            "lock tables, change column types, or add constraints that "
            "affect running pipelines and query performance."
        ),
    ),
    # -- PII handling --
    RiskPattern(
        pattern=(
            r"\bpii\b"
            r"|\bpersonal[_\-]data\b"
            r"|\bpersonally[_\-]identifiable\b"
        ),
        target="any",
        risk_contribution=0.85,
        name="pii_reference",
        description=(
            "Operations referencing PII (personally identifiable "
            "information) require extra scrutiny to prevent data leakage "
            "and ensure compliance with privacy regulations."
        ),
    ),
    RiskPattern(
        pattern=(
            r"\bemail[_\-]?address(?:es)?\b"
            r"|\bssn\b"
            r"|\bsocial[_\-]security\b"
            r"|\bdate[_\-]of[_\-]birth\b"
            r"|\bphone[_\-]number\b"
        ),
        target="any",
        risk_contribution=0.80,
        name="pii_field_access",
        description=(
            "Access to fields containing email addresses, SSNs, dates "
            "of birth, or phone numbers carries privacy risk. These "
            "columns should be masked or tokenized in non-production "
            "environments."
        ),
    ),
    # -- Production database access --
    RiskPattern(
        pattern=(
            r"\bprod(?:uction)?[_\-.]?db\b"
            r"|\bprod[_\-](?:warehouse|redshift|bigquery|snowflake)\b"
            r"|\bconnect[_\-]prod\b"
        ),
        target="any",
        risk_contribution=0.80,
        name="prod_database_access",
        description=(
            "Direct access to production databases or data warehouses "
            "bypasses application-level safeguards and may affect live "
            "workloads."
        ),
    ),
    RiskPattern(
        pattern=(
            r"\bwrite[_\-](?:to[_\-])?prod\b"
            r"|\binsert[_\-](?:into[_\-])?prod\b"
            r"|\bupdate[_\-]prod\b"
        ),
        target="any",
        risk_contribution=0.85,
        name="prod_write",
        description=(
            "Write operations to production data stores can corrupt "
            "data or introduce inconsistencies visible to end users."
        ),
    ),
    # -- ETL job modifications --
    RiskPattern(
        pattern=(
            r"\bmodify[_\-](?:etl|elt|pipeline|dag)\b"
            r"|\bupdate[_\-](?:etl|elt|pipeline|dag)\b"
            r"|\bdelete[_\-](?:etl|elt|pipeline|dag)\b"
        ),
        target="any",
        risk_contribution=0.65,
        name="etl_job_modification",
        description=(
            "ETL/ELT job modifications change how data flows between "
            "systems. Incorrect transformations can silently corrupt "
            "downstream datasets."
        ),
    ),
    RiskPattern(
        pattern=(
            r"\bairflow\b.*\b(?:trigger|clear|delete)\b"
            r"|\bdag[_\-](?:trigger|pause|delete)\b"
        ),
        target="any",
        risk_contribution=0.65,
        name="airflow_dag_change",
        description=(
            "Airflow DAG operations (trigger, clear, delete) affect "
            "scheduled data workflows. Clearing tasks reruns pipelines "
            "and may produce duplicate data."
        ),
    ),
    # -- Data export / dump --
    RiskPattern(
        pattern=(
            r"\bexport[_\-](?:data|table|database)\b"
            r"|\bdata[_\-]dump\b"
            r"|\bdump[_\-](?:table|database|schema)\b"
            r"|\bmysqldump\b|\bpg_dump\b"
        ),
        target="any",
        risk_contribution=0.70,
        name="data_export",
        description=(
            "Data export and dump operations create copies of data "
            "outside the primary storage system. Exports may contain "
            "sensitive information and must be handled securely."
        ),
    ),
    RiskPattern(
        pattern=(
            r"\bunload\b.*\bs3\b"
            r"|\bcopy\s+into\b"
            r"|\bexport[_\-]to[_\-](?:s3|gcs|blob)\b"
        ),
        target="any",
        risk_contribution=0.75,
        name="cloud_data_export",
        description=(
            "Exporting data to cloud storage (S3, GCS, Azure Blob) "
            "moves data outside the database security perimeter. "
            "Bucket permissions and encryption must be verified."
        ),
    ),
    # -- Backup / restore --
    RiskPattern(
        pattern=(
            r"\brestore[_\-](?:backup|database|snapshot)\b"
            r"|\bdb[_\-]restore\b"
            r"|\brestore[_\-]from[_\-](?:s3|gcs|backup)\b"
        ),
        target="any",
        risk_contribution=0.75,
        name="backup_restore",
        description=(
            "Restoring from backup overwrites the current data state. "
            "Any changes made after the backup timestamp will be lost."
        ),
    ),
    RiskPattern(
        pattern=(
            r"\bdelete[_\-](?:backup|snapshot)\b"
            r"|\bremove[_\-]backup\b"
            r"|\bpurge[_\-]snapshot\b"
        ),
        target="any",
        risk_contribution=0.90,
        name="backup_deletion",
        description=(
            "Deleting backups or snapshots removes the last line of "
            "defence against data loss. Recovery may be impossible "
            "after backup deletion."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Escalation rules
# ---------------------------------------------------------------------------

_DATA_PIPELINE_ESCALATION_RULES: list[EscalationRule] = [
    EscalationRule(
        condition="matches_pattern:drop_table",
        action="block",
        required_approvers=1,
        notify_roles=["data_engineering_lead"],
        description=(
            "DROP TABLE / DROP DATABASE is blocked by default. It must "
            "be authorized through an explicit data change request."
        ),
    ),
    EscalationRule(
        condition="matches_pattern:backup_deletion",
        action="block",
        required_approvers=1,
        notify_roles=["data_engineering_lead", "ops_lead"],
        description=(
            "Backup deletion is blocked by default to preserve recovery options. Requires explicit authorization."
        ),
    ),
    EscalationRule(
        condition="matches_pattern:pii_reference",
        action="require_teach_back",
        required_approvers=1,
        notify_roles=["data_privacy_lead"],
        description=(
            "Operations involving PII require the operator to confirm "
            "they understand data handling requirements and that "
            "appropriate masking or consent is in place."
        ),
    ),
    EscalationRule(
        condition="risk_score >= 0.85",
        action="require_multi_party",
        required_approvers=2,
        notify_roles=["data_engineering_lead", "on_call_engineer"],
        description=(
            "High-risk data operations require dual approval from the data engineering lead and on-call engineer."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Challenge templates
# ---------------------------------------------------------------------------

_DATA_PIPELINE_CHALLENGE_TEMPLATES: list[DomainChallengeTemplate] = [
    DomainChallengeTemplate(
        question_template=(
            "Does '{function_name}' affect production data? If so, has a backup been taken and verified?"
        ),
        answer_hints=[
            "yes",
            "backup",
            "snapshot",
            "verified",
            "no",
            "staging",
            "development",
        ],
        context_vars=["function_name"],
        challenge_type="quiz",
        min_risk_level="high",
    ),
    DomainChallengeTemplate(
        question_template=(
            "Does this operation involve PII or sensitive data? "
            "Describe the data classification and handling procedures."
        ),
        answer_hints=[
            "pii",
            "personal",
            "masked",
            "anonymized",
            "encrypted",
            "tokenized",
            "no pii",
        ],
        context_vars=["function_name"],
        challenge_type="teach_back",
        min_risk_level="medium",
    ),
    DomainChallengeTemplate(
        question_template=(
            "What downstream systems or dashboards depend on the data "
            "modified by '{function_name}'? What is the recovery plan "
            "if the operation fails?"
        ),
        answer_hints=[
            "downstream",
            "dashboard",
            "consumer",
            "rollback",
            "restore",
            "revert",
            "backfill",
        ],
        context_vars=["function_name"],
        challenge_type="teach_back",
        min_risk_level="high",
    ),
    DomainChallengeTemplate(
        question_template=(
            "Has the schema migration been tested against a copy of production data? Provide the test reference."
        ),
        answer_hints=[
            "tested",
            "staging",
            "pre-production",
            "passed",
            "verified",
            "dry run",
        ],
        context_vars=["function_name"],
        challenge_type="quiz",
        min_risk_level="high",
    ),
]


# ---------------------------------------------------------------------------
# Profile definition
# ---------------------------------------------------------------------------

DATA_PIPELINE_PROFILE = DomainProfile(
    name="data-pipeline",
    display_name="Data Pipeline",
    description=(
        "Heuristic-only domain profile for data engineering and "
        "ETL/ELT teams. Covers data deletion and truncation, schema "
        "migrations (ALTER TABLE, Alembic, Flyway), PII handling "
        "(personal data, emails, SSNs), production database access, "
        "ETL/ELT job modifications (Airflow DAGs), data export and "
        "dump operations, and backup/restore workflows. No LLM or "
        "regulated-compliance dependencies."
    ),
    risk_patterns=_DATA_PIPELINE_RISK_PATTERNS,
    sensitive_terms={
        "production": 0.7,
        "pii": 0.9,
        "personal data": 0.9,
        "ssn": 0.95,
        "email address": 0.7,
        "delete": 0.6,
        "truncate": 0.8,
        "drop": 0.8,
        "migration": 0.5,
        "backup": 0.5,
        "restore": 0.6,
        "export": 0.5,
        "dump": 0.6,
        "sensitive": 0.7,
        "confidential": 0.8,
    },
    critical_actions=[
        "drop_table",
        "drop_database",
        "truncate_table",
        "delete_backup",
        "purge_production_data",
    ],
    safe_actions=[
        "list_tables",
        "describe_table",
        "get_schema",
        "check_pipeline_status",
        "view_dag_status",
        "get_row_count",
        "preview_data",
        "dry_run_migration",
    ],
    escalation_rules=_DATA_PIPELINE_ESCALATION_RULES,
    challenge_templates=_DATA_PIPELINE_CHALLENGE_TEMPLATES,
    min_review_overrides={
        "critical": 30.0,
        "high": 10.0,
    },
    base_risk_floor=0.05,
    production_multiplier=1.5,
    required_vocabulary=[
        "backup",
        "restore",
        "migration",
        "schema",
        "downstream",
        "rollback",
    ],
)


# ---------------------------------------------------------------------------
# Auto-register with the global registry
# ---------------------------------------------------------------------------

if DATA_PIPELINE_PROFILE.name not in registry:
    registry.register(DATA_PIPELINE_PROFILE)
