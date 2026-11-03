"""Tests for agentguard.events."""

import json
from pathlib import Path

import pytest
from agentguard.events import EventBus, JSONLFileSink, get_event_bus, reset_event_bus
from agentguard.schemas import TraceEvent


def test_event_bus_two_subscribers():
    bus = EventBus()
    calls1 = []
    calls2 = []
    bus.subscribe(lambda e: calls1.append(e))
    bus.subscribe(lambda e: calls2.append(e))

    evt = TraceEvent(source="test", event_type="probe_sent", payload={"probe": "hi"})
    bus.emit(evt)

    assert len(calls1) == 1
    assert calls1[0] == evt
    assert len(calls2) == 1
    assert calls2[0] == evt


def test_event_bus_error_resilience():
    bus = EventBus()
    calls = []

    def broken_subscriber(e):
        raise RuntimeError("boom")

    bus.subscribe(broken_subscriber)
    bus.subscribe(lambda e: calls.append(e))

    evt = TraceEvent(source="test", event_type="test_event")
    # Must not raise
    bus.emit(evt)

    assert len(calls) == 1
    assert calls[0] == evt


def test_jsonl_file_sink(tmp_path: Path):
    sink_file = tmp_path / "events.jsonl"
    sink = JSONLFileSink(sink_file)

    events = [
        TraceEvent(source="s1", event_type="e1", payload={"a": 1}),
        TraceEvent(source="s2", event_type="e2", payload={"b": 2}),
        TraceEvent(source="s3", event_type="e3", payload={"c": 3}),
    ]

    for e in events:
        sink(e)

    lines = sink_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 3

    for line, original in zip(lines, events):
        data = json.loads(line)
        reconstructed = TraceEvent.model_validate_json(line)
        assert reconstructed.source == original.source
        assert reconstructed.event_type == original.event_type
        assert reconstructed.payload == original.payload


def test_get_event_bus_singleton_and_reset():
    reset_event_bus()
    b1 = get_event_bus()
    b2 = get_event_bus()
    assert b1 is b2

    reset_event_bus()
    b3 = get_event_bus()
    assert b3 is not b1
