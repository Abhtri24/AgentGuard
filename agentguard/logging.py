"""Logging utilities for AgentGuard."""

from __future__ import annotations

import logging
import sys
from typing import Optional

LOGGER_NAME = "agentguard"


def setup_logging(
    level: Optional[str] = None,
    verbose: bool = False,
    quiet: bool = False,
) -> logging.Logger:
    """Configure the root agentguard logger.

    verbose: sets level to DEBUG
    quiet: sets level to ERROR
    level: explicit string level e.g. 'DEBUG', 'INFO', 'WARNING', 'ERROR'
    """
    logger = logging.getLogger(LOGGER_NAME)

    if quiet:
        target_level = logging.ERROR
    elif verbose:
        target_level = logging.DEBUG
    elif level:
        target_level = getattr(logging, level.upper(), logging.INFO)
    else:
        target_level = logging.INFO

    logger.setLevel(target_level)

    # Avoid adding duplicate handlers if already configured
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    else:
        for handler in logger.handlers:
            handler.setLevel(target_level)

    return logger


def get_logger(subname: Optional[str] = None) -> logging.Logger:
    """Get a child logger under the 'agentguard' hierarchy."""
    if subname:
        return logging.getLogger(f"{LOGGER_NAME}.{subname}")
    return logging.getLogger(LOGGER_NAME)
