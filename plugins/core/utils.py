"""
Common utility functions for plugins.
"""
import re
from typing import Any


def is_valid_url(url: str) -> bool:
    """Check if a string is a valid URL."""
    return url.startswith(("http://", "https://"))


def sanitize_string(input_str: str) -> str:
    """Remove potentially dangerous characters."""
    return re.sub(r"[^a-zA-Z0-9_\-\.]", "", input_str)


def merge_dicts(dict1: dict[str, Any], dict2: dict[str, Any]) -> dict[str, Any]:
    """Deep merge two dictionaries."""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    return result
