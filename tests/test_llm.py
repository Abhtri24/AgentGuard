from unittest.mock import MagicMock, patch
from agentguard.config import normalize_model
from agentguard.llm import chat


def test_normalize_model_providers(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk_dummy")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    assert normalize_model("openai/gpt-oss-20b") == "groq/openai/gpt-oss-20b"
    assert normalize_model("gpt-4o") == "openai/gpt-4o"
    assert normalize_model("claude-3-5-sonnet") == "anthropic/claude-3-5-sonnet"
    assert normalize_model("gemini-2.0-flash") == "gemini/gemini-2.0-flash"
    assert normalize_model("groq/openai/gpt-oss-20b") == "groq/openai/gpt-oss-20b"


@patch("litellm.completion")
def test_chat_formats_response_correctly(mock_completion):
    mock_choice = MagicMock()
    mock_choice.message.role = "assistant"
    mock_choice.message.content = "Test answer"
    mock_choice.message.tool_calls = None

    mock_resp = MagicMock()
    mock_resp.choices = [mock_choice]
    mock_resp.model = "test-model"
    mock_resp.usage = {"total_tokens": 10}
    mock_completion.return_value = mock_resp

    result = chat(
        messages=[{"role": "user", "content": "hello"}],
        model="test-model",
    )

    assert result["choices"][0]["message"]["content"] == "Test answer"
    assert result["choices"][0]["message"]["role"] == "assistant"
    assert result["choices"][0]["message"]["tool_calls"] == []
    assert result["model"] == "test-model"


@patch("litellm.completion")
def test_chat_handles_tool_calls(mock_completion):
    mock_tool = MagicMock()
    mock_tool.id = "call_abc"
    mock_tool.type = "function"
    mock_tool.function.name = "execute_action"
    mock_tool.function.arguments = '{"target": "db"}'

    mock_choice = MagicMock()
    mock_choice.message.role = "assistant"
    mock_choice.message.content = ""
    mock_choice.message.tool_calls = [mock_tool]

    mock_resp = MagicMock()
    mock_resp.choices = [mock_choice]
    mock_resp.model = "test-model"
    mock_completion.return_value = mock_resp

    result = chat(
        messages=[{"role": "user", "content": "do action"}],
        tools=[{"type": "function", "function": {"name": "execute_action"}}],
        model="test-model",
    )

    calls = result["choices"][0]["message"]["tool_calls"]
    assert len(calls) == 1
    assert calls[0]["id"] == "call_abc"
    assert calls[0]["function"]["name"] == "execute_action"
    assert calls[0]["function"]["arguments"] == '{"target": "db"}'
