# Error Capture

Most pyxecm methods return `None` (or `False`) in case of an error and write the reason to the log.
Callers that need the reason (e.g. AI agents or MCP tools) can wrap their calls in a
`capture_errors()` block. Return values and logging do not change.

```python
from pyxecm import ErrorCategory, capture_errors

with capture_errors() as errors:
    node = otcs.create_item(parent_id=4711, item_name="Contracts", item_type=otcs.ITEM_TYPE_FOLDER)

if errors.root_cause and errors.root_cause.category == ErrorCategory.ALREADY_EXISTS:
    ...
elif node is None:
    raise RuntimeError(errors.to_agent_message(fallback="Failed to create folder"))
```

Errors are collected as `PyxecmError` objects - one subclass per module (`OTCSError`, `OTDSError`, ...),
so `isinstance()` or `errors.of_type(OTCSError)` tell where an error comes from. They describe errors and
are collected, not raised.

Each error has a `category` (e.g. `not_found`, `permission_denied`, `already_exists`),
a `severity` matching the log level (`debug` is used for failures the code expects, like a
lookup that checks if an item exists), the HTTP `status_code`, the `server_message` returned
by Content Server and the `method` and `url` (without query string) of the failed REST call.

`ErrorCollector.root_cause` ignores `debug` records (unless there is nothing else), prefers
records with a known category and takes the most recent one.

The collector is stored in a context variable: it works in the current thread and in asyncio
tasks, but threads must be started with `contextvars.copy_context().run` to report into it.

Errors are recorded by all API classes with their own error class: `OTCS` (`OTCSError`), `OTDS` (`OTDSError`),
`OTAWP`, `OTAC`, `OTCA`, `OTKD`, `OTMM`, `OTPD`, `AVTS` and `CoreShare` (`OTAWPError`, ... `CoreShareError`).
In `pyxecm_customizer`, the `SAP` class records `SAPError` (`from pyxecm_customizer.sap import SAPError`) -
in addition to its existing `last_error` property, which is unchanged.

## Recording errors in pyxecm code

The `logger` of these classes is a `ReportingLogger` (set up with `ReportingLoggerAttribute`): it behaves like a normal `logging.Logger`, but its
`error()` and `warning()` methods also accept `report=True`. Use it where a method gives up
and the message explains why - typically right before `return None` / `return False`:

```python
if not response:
    self.logger.error("Volume type -> %s not found!", str(volume_type), report=True)
    return None
```

Add `category=ErrorCategory....` if the message text does not tell the reason clearly.
Don't use `report=True` for messages that don't explain a failure of the method, like retry
messages or warnings the method recovers from. Failed REST calls are recorded by
`do_request()` automatically (it calls `record_request_error()` at its final failure exits).

A new API class gets the same behavior with its own error class in `errors.py` and
`logger = ReportingLoggerAttribute(default_logger, error_class=MyError)` as class attribute.

::: pyxecm.errors
