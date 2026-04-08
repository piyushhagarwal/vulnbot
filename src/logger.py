import logging
import sys


def get_logger(name: str) -> logging.Logger:
    """Returns a logger for the given module name."""
    return logging.getLogger(name)


def setup_logging(level: str = "INFO") -> None:
    """
    Configure root logger once at startup.
    All module loggers inherit this config.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(numeric_level)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(numeric_level)
    root.addHandler(handler)