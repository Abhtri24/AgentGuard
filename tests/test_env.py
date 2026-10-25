import os
from pathlib import Path
from agentguard._env import load_env


def test_load_env_strips_quotes_and_comments(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        """
        # A comment line
        GROQ_TEST_KEY_RAW=raw_value
        GROQ_TEST_KEY_DOUBLE="double_quoted_value"
        GROQ_TEST_KEY_SINGLE='single_quoted_value'
        INVALID_LINE_NO_EQUALS
        
        ANOTHER_KEY = with_spaces
        """,
        encoding="utf-8",
    )

    load_env(env_path=env_file, force_reload=True)

    assert os.environ.get("GROQ_TEST_KEY_RAW") == "raw_value"
    assert os.environ.get("GROQ_TEST_KEY_DOUBLE") == "double_quoted_value"
    assert os.environ.get("GROQ_TEST_KEY_SINGLE") == "single_quoted_value"
    assert os.environ.get("ANOTHER_KEY") == "with_spaces"
