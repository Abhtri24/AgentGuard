import httpx
import pytest
import respx
from agentguard.target import Target


def test_target_session_id():
    with Target("http://127.0.0.1:8000") as target:
        sid1 = target.new_session_id()
        sid2 = target.new_session_id()
        assert len(sid1) == 32
        assert sid1 != sid2


@respx.mock
def test_target_health():
    respx.get("http://127.0.0.1:8000/health").respond(200, json={"status": "ok", "entrypoint_registered": True})

    with Target("http://127.0.0.1:8000") as target:
        health = target.health()
        assert health["status"] == "ok"
        assert health["entrypoint_registered"] is True


@respx.mock
def test_target_invoke_success():
    respx.post("http://127.0.0.1:8000/invoke").respond(
        200,
        json={"output": "Done", "tool_calls": [], "error": None, "latency_ms": 12.5},
    )

    with Target("http://127.0.0.1:8000") as target:
        resp = target.invoke("test prompt", session_id="s1")
        assert resp["output"] == "Done"
        assert resp["error"] is None


@respx.mock
def test_target_invoke_handles_500_without_raising():
    respx.post("http://127.0.0.1:8000/invoke").respond(
        500,
        text="Internal Server Error in Target",
    )

    with Target("http://127.0.0.1:8000") as target:
        resp = target.invoke("crash prompt")
        assert resp["output"] is None
        assert resp["error"] is not None
        assert resp["error"]["type"] == "TargetHTTPError"
        assert "500" in resp["error"]["detail"]


@respx.mock
def test_target_invoke_handles_network_error_without_raising():
    respx.post("http://127.0.0.1:8000/invoke").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )

    with Target("http://127.0.0.1:8000") as target:
        resp = target.invoke("network failure prompt")
        assert resp["output"] is None
        assert resp["error"] is not None
        assert resp["error"]["type"] == "ConnectError"
