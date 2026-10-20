"""OpenTelemetry spans for every tool decision.

Attribute names follow the OpenTelemetry GenAI semantic conventions,
execute_tool span, status Development, as published in
open-telemetry/semantic-conventions-genai (checked 2026-10-20).
Custom attributes use the atg.* prefix.
"""

from __future__ import annotations

import json
from pathlib import Path

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.trace import Status, StatusCode

GENAI_SEMCONV = "gen-ai execute_tool (development), semantic-conventions-genai main @ 2026-10-20"


class JsonlSpanExporter(SpanExporter):
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def export(self, spans) -> SpanExportResult:
        with self.path.open("a", encoding="utf-8") as handle:
            for span in spans:
                handle.write(
                    json.dumps(
                        {
                            "name": span.name,
                            "trace_id": format(span.context.trace_id, "032x"),
                            "span_id": format(span.context.span_id, "016x"),
                            "start_ns": span.start_time,
                            "end_ns": span.end_time,
                            "status": span.status.status_code.name,
                            "attributes": dict(span.attributes or {}),
                        },
                        default=str,
                    )
                    + "\n"
                )
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


class Telemetry:
    def __init__(self, *, span_path: Path | None = None, otlp_endpoint: str | None = None):
        resource = Resource.create({"service.name": "agent-trust-gateway"})
        provider = TracerProvider(resource=resource)
        if span_path is not None:
            provider.add_span_processor(SimpleSpanProcessor(JsonlSpanExporter(span_path)))
        if otlp_endpoint:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            provider.add_span_processor(
                SimpleSpanProcessor(OTLPSpanExporter(endpoint=f"{otlp_endpoint.rstrip('/')}/v1/traces"))
            )
        self.provider = provider
        self.tracer = provider.get_tracer("agent-trust-gateway", "0.1.0")

    def shutdown(self) -> None:
        self.provider.shutdown()

    def decision_span(self, **attributes: object):
        name = f"execute_tool {attributes.get('gen_ai.tool.name', 'unknown')}"
        return self.tracer.start_as_current_span(name, attributes=_primitive(attributes))


def _primitive(attributes: dict) -> dict:
    cleaned = {}
    for key, value in attributes.items():
        if value is None:
            continue
        if isinstance(value, (str, bool, int, float)):
            cleaned[key] = value
        elif isinstance(value, (list, tuple)):
            cleaned[key] = ",".join(str(item) for item in value)
        else:
            cleaned[key] = str(value)
    return cleaned


def mark_status(span, decision: str) -> None:
    if decision == "allow":
        span.set_status(Status(StatusCode.OK))
    else:
        span.set_status(Status(StatusCode.ERROR, decision))


def current_tracer() -> trace.Tracer:
    return trace.get_tracer("agent-trust-gateway")
