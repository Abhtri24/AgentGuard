import time
import pytest
from agentguard.ratelimit import RateLimiter, get_rate_limiter


def test_ratelimiter_sync_spacing():
    limiter = RateLimiter(default_cooldown=0.05)
    t0 = time.monotonic()
    limiter.sync_wait_for_slot()
    limiter.sync_wait_for_slot()
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.04


@pytest.mark.asyncio
async def test_ratelimiter_async_spacing():
    limiter = RateLimiter(default_cooldown=0.05)
    t0 = time.monotonic()
    await limiter.wait_for_slot()
    await limiter.wait_for_slot()
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.04


def test_get_global_rate_limiter():
    limiter = get_rate_limiter()
    assert isinstance(limiter, RateLimiter)
