"""Rate limiting and backoff utilities for multi-provider LLM calls."""

from __future__ import annotations

import asyncio
import time
from typing import Optional

from agentguard.logging import get_logger

logger = get_logger("ratelimit")


class RateLimiter:
    """Manages call spacing and adaptive backoff across API calls."""

    def __init__(self, default_cooldown: float = 2.0, max_backoff: float = 60.0):
        self.default_cooldown = default_cooldown
        self.max_backoff = max_backoff
        self._last_call_time: float = 0.0

    async def wait_for_slot(self, cooldown: Optional[float] = None) -> None:
        """Asynchronously wait if needed to respect cooldown spacing."""
        delay = cooldown if cooldown is not None else self.default_cooldown
        if delay <= 0:
            return
        now = time.monotonic()
        elapsed = now - self._last_call_time
        if elapsed < delay:
            wait_time = delay - elapsed
            logger.debug("RateLimiter slot wait: sleeping %.2fs", wait_time)
            await asyncio.sleep(wait_time)
        self._last_call_time = time.monotonic()

    def sync_wait_for_slot(self, cooldown: Optional[float] = None) -> None:
        """Synchronously wait if needed to respect cooldown spacing."""
        delay = cooldown if cooldown is not None else self.default_cooldown
        if delay <= 0:
            return
        now = time.monotonic()
        elapsed = now - self._last_call_time
        if elapsed < delay:
            wait_time = delay - elapsed
            logger.debug("RateLimiter sync wait: sleeping %.2fs", wait_time)
            time.sleep(wait_time)
        self._last_call_time = time.monotonic()


_global_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = RateLimiter()
    return _global_limiter
