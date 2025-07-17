"""Define OpenTelemtry configuration."""

import os

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.threading import ThreadingInstrumentor
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

resource = Resource.create(attributes={SERVICE_NAME: "pyxecm"})

trace.set_tracer_provider(TracerProvider(resource=resource))

if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
    trace.get_tracer_provider().add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter()),
    )

# Auto-instrument requests
RequestsInstrumentor().instrument()
ThreadingInstrumentor().instrument()

tracer = trace.get_tracer("pyxecm")
