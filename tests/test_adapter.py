from fastapi.testclient import TestClient
from agentguard.adapter import app, expose, watch, _bind


client = TestClient(app)


def test_bind_arguments():
    def dummy_func(a, b=10, *args, c=20, **kwargs):
        pass

    bound = _bind(dummy_func, (1,), {"c": 30, "extra": "val"})
    assert bound["a"] == 1
    assert bound["b"] == 10
    assert bound["c"] == 30
    assert bound["kwargs"] == {"extra": "val"}


def test_watch_tracks_calls():
    @watch
    def my_tool(x, y=5):
        return x + y

    # When called outside invoke context, watch executes normally without error
    result = my_tool(10, y=20)
    assert result == 30


def test_invoke_lifecycle_with_tool_calls():
    @watch
    def sample_tool(account: str, amount: float):
        return f"transferred {amount} to {account}"

    @expose
    def run_agent(input_text: str, session_id: str = None):
        sample_tool("Alice", 100.0)
        return f"Processed '{input_text}' for session {session_id}"

    # Verify health endpoint
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["entrypoint_registered"] is True

    # Call /invoke
    resp = client.post("/invoke", json={"input_text": "hello agent", "session_id": "sess-123"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["output"] == "Processed 'hello agent' for session sess-123"
    assert data["error"] is None
    assert len(data["tool_calls"]) == 1
    call = data["tool_calls"][0]
    assert call["name"] == "sample_tool"
    assert call["args"]["account"] == "Alice"
    assert call["args"]["amount"] == 100.0


def test_invoke_handles_exceptions_gracefully():
    @expose
    def faulty_agent(input_text: str):
        if "fail" in input_text:
            raise ValueError("Deliberate failure inside agent")
        return "ok"

    resp = client.post("/invoke", json={"input_text": "please fail"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["output"] is None
    assert data["error"] == {
        "type": "ValueError",
        "detail": "Deliberate failure inside agent",
    }
