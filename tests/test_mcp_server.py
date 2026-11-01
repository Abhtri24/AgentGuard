from agentguard.mcp_server import configure_target_directory, owasp_lookup, search_code


def test_owasp_lookup_known_category():
    assert "LLM06" in owasp_lookup("tool_misuse")


def test_owasp_lookup_unknown_category():
    assert owasp_lookup("unknown") == "unknown category: unknown"


def test_search_code_refuses_path_outside_target(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    configure_target_directory(target)
    assert "refused" in search_code("secret", str(tmp_path))


def test_search_code_results_are_bounded(tmp_path):
    configure_target_directory(tmp_path)
    (tmp_path / "app.py").write_text("needle " + "x" * 5000, encoding="utf-8")
    result = search_code("needle", str(tmp_path), max_results=20)
    assert "app.py:1:needle" in result
    assert len(result) <= 4000
