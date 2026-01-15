"""Output utilities for RedSurface."""

from pathlib import Path
from typing import Any


def ensure_output_dir(output_path: Path) -> Path:
    """
    Ensure the output directory exists.

    Args:
        output_path: Path to output directory

    Returns:
        Resolved output path
    """
    output_path = output_path.resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    return output_path
