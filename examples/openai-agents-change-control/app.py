"""OpenAI Agents approval-gating skeleton for production change control."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from attesta import Attesta, AttestaDenied
from attesta.integrations.openai_sdk import attesta_approval_handler


@dataclass
class ChangeRequest:
    ticket_id: str
    sql: str
    environment: str = "production"


attesta = Attesta.from_config("attesta.yaml")
approval_handler = attesta_approval_handler(attesta)


async def execute_sql_change(change: ChangeRequest) -> str:
    approved = await approval_handler(
        "execute_sql_change",
        {
            "change_ticket": change.ticket_id,
            "sql": change.sql,
            "environment": change.environment,
            "data_write": True,
        },
    )

    if not approved:
        raise AttestaDenied(
            f"Change {change.ticket_id} was denied or escalated and must be handled out-of-band"
        )

    # Replace with your real tool execution path.
    return f"Executed ticket {change.ticket_id}"


async def main() -> None:
    request = ChangeRequest(
        ticket_id="CHG-4821",
        sql="DROP TABLE users_archive;",
    )

    try:
        result = await execute_sql_change(request)
    except AttestaDenied as exc:
        print(f"Blocked: {exc}")
        return

    print(result)


if __name__ == "__main__":
    asyncio.run(main())
