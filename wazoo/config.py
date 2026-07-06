import logging
from typing import Any
import yaml


def load_config(path: str, **args: Any) -> dict[str, Any]:
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    return {**args, **data}


def configureLogging(
    verbose: bool = False,
    console: bool = True,
):
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(filename)s.%(funcName)s]: %(message)s"
    )

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    if console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root.addHandler(console_handler)
