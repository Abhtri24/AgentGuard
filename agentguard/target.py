"""Client-side handle for a running agentguard-adapter target."""

from __future__ import annotations

import time
import uuid
from typing import Any, Optional

import httpx

from agentguard.config import get_config
from agentguard.logging import get_logger

logger = get_logger("target")


class Target:
    """HTTP client for a target app instrumented with @expose / @watch."""

    def __init__(self, url: str, timeout: Optional[float] = None):
        self.url = url.rstrip("/")
        self._timeout = (
            timeout if timeout is not None else get_config().target_timeout
        )
        self._client = httpx.Client(base_url=self.url, timeout=self._timeout)

    def new_session_id(self) -> str:
        return uuid.uuid4().hex

    def health(self) -> dict:
        """Query /health endpoint to verify target responsiveness."""
        try:
            resp = self._client.get("/health")
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.warning("Target health check failed on %s: %s", self.url, exc)
            raise

    def invoke(self, input_text: str, session_id: Optional[str] = None) -> dict:
        """POST /invoke and return {output, tool_calls, error, latency_ms}.

        Never raises on target-side failures or connection errors — those come back as the
        `error` field so an attack loop can keep going.
        """
        payload = {"input_text": input_text, "session_id": session_id}
        t0 = time.perf_counter()
        try:
            logger.debug("Invoking target at %s/invoke with session=%s", self.url, session_id)
            resp = self._client.post("/invoke", json=payload)
            latency_ms = (time.perf_counter() - t0) * 1000

            # If the response is JSON, return it (it may already contain an error field)
            try:
                data = resp.json()
                if "latency_ms" not in data:
                    data["latency_ms"] = latency_ms
                if resp.status_code >= 400 and not data.get("error"):
                    data["error"] = {
                        "type": "TargetHTTPError",
                        "detail": f"HTTP {resp.status_code}: {resp.text}",
                    }
                return data
            except Exception:
                return {
                    "output": None,
                    "tool_calls": [],
                    "error": {
                        "type": "TargetHTTPError",
                        "detail": f"HTTP {resp.status_code}: {resp.text}",
                    },
                    "latency_ms": latency_ms,
                }
        except httpx.RequestError as exc:
            latency_ms = (time.perf_counter() - t0) * 1000
            logger.warning("Target invocation request error: %s", exc)
            return {
                "output": None,
                "tool_calls": [],
                "error": {"type": type(exc).__name__, "detail": str(exc)},
                "latency_ms": latency_ms,
            }

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "Target":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
