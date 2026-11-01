"""Tests for agentguard.schemas."""

import pytest
from agentguard.schemas import (
    AttemptStatus,
    BudgetUsage,
    Finding,
    OracleType,
    ProbeOutcome,
    ToolCallRecord,
    TraceEvent,
    Turn,
)


def test_finding_default_status_and_success():
    f = Finding(category="prompt_injection", capability_targeted="system_prompt")
    assert f.status == AttemptStatus.FAILED
    assert f.success is False
    assert f.confidence == 0.0


def test_finding_confirmed_status_success():
    f = Finding(
        category="prompt_injection",
        capability_targeted="system_prompt",
        status=AttemptStatus.CONFIRMED,
    )
    assert f.success is True


def test_finding_suspected_status_success():
    f = Finding(
        category="prompt_injection",
        capability_targeted="system_prompt",
        status=AttemptStatus.SUSPECTED,
    )
    assert f.success is True


def test_finding_json_roundtrip():
    turn = Turn(
        sent="test prompt",
        received="test output",
        tool_calls=[ToolCallRecord(name="tool_a", args={"k": "v"})],
        outcome=ProbeOutcome.SUCCESS,
    )
    f = Finding(
        category="tool_misuse",
        capability_targeted="destructive_tool",
        turns=[turn],
        oracle=OracleType.SIDE_EFFECT,
        oracle_detail="tool_a called",
        status=AttemptStatus.CONFIRMED,
        confidence=1.0,
    )
    serialized = f.model_dump_json()
    reconstructed = Finding.model_validate_json(serialized)
    assert reconstructed.id == f.id
    assert reconstructed.category == f.category
    assert reconstructed.status == AttemptStatus.CONFIRMED
    assert reconstructed.oracle == OracleType.SIDE_EFFECT
    assert len(reconstructed.turns) == 1
    assert reconstructed.turns[0].sent == "test prompt"
    assert reconstructed.turns[0].tool_calls[0].name == "tool_a"
    assert reconstructed.success is True


def test_turn_default_outcome():
    t = Turn(sent="hello")
    assert t.outcome == ProbeOutcome.INCONCLUSIVE
    assert t.tool_calls == []
    assert t.received is None


def test_budget_usage_total_tokens():
    b = BudgetUsage(calls=2, prompt_tokens=50, completion_tokens=25)
    assert b.total_tokens == 75
