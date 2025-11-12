"""Shared logging utilities."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from rich.logging import RichHandler


def setup_logging(
    level: int = logging.INFO,
    *,
    extra_handlers: Iterable[logging.Handler] | None = None,
) -> None:
    """
    Configure root logging with sensible defaults for both demos.

    Parameters
    ----------
    level:
        Desired logging level.
    extra_handlers:
        Optional iterable of additional handlers to attach to the root logger.
    """

    if logging.getLogger().handlers:
        # Avoid reconfiguring if handlers are already present.
        return

    rich_handler = RichHandler(rich_tracebacks=True, markup=False)
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[rich_handler, *(extra_handlers or ())],
    )

