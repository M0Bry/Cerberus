"""Date, size, JSON formatting utilities."""

from datetime import datetime


def format_date(dt: datetime | None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format a datetime object to a string, or return empty string if None."""
    return dt.strftime(fmt) if dt else ""


def format_file_size(size_bytes: int) -> str:
    """Convert file size in bytes to a human-readable string."""
    current = float(size_bytes)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if current < 1024:
            return f"{current:.1f} {unit}"
        current /= 1024
    return f"{current:.1f} TB"
