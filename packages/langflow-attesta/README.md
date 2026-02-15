# langflow-attesta

Langflow component for [Attesta](https://attesta.dev) human-in-the-loop approval gates.

This is a **Langflow contribution-ready component** — it's designed to be added directly to the Langflow source tree, not installed as a standalone pip package.

## Contributing to Langflow

To add this component to Langflow, follow the [Langflow contributing components guide](https://docs.langflow.org/contributing-components):

1. Copy `attesta_gate.py` into the Langflow source tree:

   ```bash
   cp attesta_gate.py /path/to/langflow/src/lfx/src/lfx/components/tools/attesta_gate.py
   ```

2. Register the component in the category's `__init__.py`:

   ```python
   # In src/lfx/src/lfx/components/tools/__init__.py
   from .attesta_gate import AttestaGate
   ```

3. Add `attesta` to the Langflow `pyproject.toml` dependencies:

   ```toml
   [project.optional-dependencies]
   attesta = ["attesta>=0.1.0"]
   ```

4. Restart Langflow. The **Attesta Approval** component appears in the Tools category.

## Using as a Custom Component

If you don't want to modify Langflow source, you can load it via `LANGFLOW_COMPONENTS_PATH`:

```bash
export LANGFLOW_COMPONENTS_PATH=/path/to/this/directory
langflow run
```

## Component Inputs

| Input | Type | Default | Description |
|---|---|---|---|
| **Function Name** | string | *(required)* | Name of the action being gated (e.g. `send_email`) |
| **Risk Level** | dropdown | `auto` | Risk level override: `auto`, `low`, `medium`, `high`, `critical` |
| **Action Arguments** | string | `{}` | JSON string of action arguments |
| **Risk Hints** | string | `{}` | JSON string of risk hints (advanced) |

## Component Output

The **Approval Result** output is a `Data` object:

| Field | Type | Description |
|---|---|---|
| `verdict` | string | `approved`, `denied`, `modified`, `timed_out`, `escalated` |
| `risk_score` | float | 0-1 risk score |
| `risk_level` | string | `low`, `medium`, `high`, `critical` |
| `denied` | bool | `true` if action was denied/timed out/escalated |
| `audit_entry_id` | string | Audit log entry ID |
| `review_time_seconds` | float | Time spent in review |

## Running Tests

```bash
cd packages/langflow-attesta
pip install attesta pytest pytest-asyncio
pytest tests/ -v
```

## License

MIT
