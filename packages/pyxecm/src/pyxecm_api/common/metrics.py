"""Metics for payload logs."""

from collections.abc import Callable

from prometheus_client import Gauge
from prometheus_fastapi_instrumentator.metrics import Info
from pyxecm_customizer.payload_list import PayloadList


## By Payload
def payload_logs_by_payload(payload_list: PayloadList) -> Callable[[Info], None]:
    """Metrics for payload logs by payload."""

    metrics_error = Gauge(
        "payload_error",
        "Number of ERROR log messages for by payload",
        labelnames=("index", "name", "logfile"),
    )

    metrics_warning = Gauge(
        "payload_warning",
        "Number of WARNING log messages for by payload",
        labelnames=("index", "name", "logfile"),
    )

    metrics_info = Gauge(
        "payload_info",
        "Number of INFO log messages for by payload",
        labelnames=("index", "name", "logfile"),
    )

    metrics_debug = Gauge(
        "payload_debug",
        "Number of DEBUG log messages for by payload",
        labelnames=("index", "name", "logfile"),
    )

    def instrumentation(info: Info) -> None:  # noqa: ARG001
        df = payload_list.get_payload_items()
        data = [{"index": idx, **row} for idx, row in df.iterrows()]

        for item in data:
            metrics_error.labels(item["index"], item["name"], item["logfile"]).set(
                item["log_error"],
            )
            metrics_warning.labels(item["index"], item["name"], item["logfile"]).set(
                item["log_warning"],
            )
            metrics_info.labels(item["index"], item["name"], item["logfile"]).set(
                item["log_info"],
            )
            metrics_debug.labels(item["index"], item["name"], item["logfile"]).set(
                item["log_debug"],
            )

    return instrumentation


## Total
def payload_logs_total(payload_list: PayloadList) -> Callable[[Info], None]:
    """Metrics for total payload logs messages."""

    metrics_error = Gauge(
        "payload_error_total",
        "Total number of ERROR log messages",
    )

    metrics_warning = Gauge(
        "payload_warning_total",
        "Total number of WARNING log messages",
    )

    metrics_info = Gauge(
        "payload_info_total",
        "Total number of INFO log messages",
    )

    metrics_debug = Gauge(
        "payload_debug_total",
        "Total number of DEBUG log messages",
    )

    def instrumentation(info: Info) -> None:  # noqa: ARG001
        df = payload_list.get_payload_items()

        metrics_error.set(df["log_error"].sum())
        metrics_warning.set(df["log_warning"].sum())
        metrics_info.set(df["log_info"].sum())
        metrics_debug.set(df["log_debug"].sum())

    return instrumentation
