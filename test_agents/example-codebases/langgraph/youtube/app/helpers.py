"""Helper functions for the application."""

from datetime import (
    datetime,
    timedelta,
)

import structlog
from django.utils import timezone

logger = structlog.get_logger(__name__)


def get_exact_time(relative_time: str) -> datetime | None:
    """Convert relative time (e.g., '3 months ago') to an exact date and time.

    Returns:
        A timezone-aware datetime object.
    """
    current_time = timezone.now()

    # Parsing relative time
    time_units = {
        "second": "seconds",
        "minute": "minutes",
        "hour": "hours",
        "day": "days",
        "week": "weeks",
        "month": "months",
        "year": "years",
    }

    try:
        # Extract number and unit from the relative time string
        parts = relative_time.split()
        number = int(parts[0])
        unit = parts[1].lower().rstrip("s")  # Normalize to singular form (e.g., "months" -> "month")

        if unit in time_units:
            if unit == "month":
                # Approximate one month as 30 days
                exact_time = current_time - timedelta(days=number * 30)
            elif unit == "year":
                # Approximate one year as 365 days
                exact_time = current_time - timedelta(days=number * 365)
            else:
                # Handle other units directly
                kwargs = {time_units[unit]: number}
                exact_time = current_time - timedelta(**kwargs)
        else:
            raise ValueError(f"Unrecognized time unit: {unit}")

        # Return timezone-aware datetime object
        return exact_time
    except Exception as e:
        logger.error("Error processing relative time", error=str(e), relative_time=relative_time)
        return None


def convert_time_to_seconds(time_str):
    """Converts HH:MM:SS or HH:MM:SS.SSS to seconds."""
    parts = time_str.split(":")
    seconds = 0
    for i, part in enumerate(reversed(parts)):
        seconds += float(part) * (60**i)
    return int(seconds)


def convert_seconds_to_timestamp(seconds: float) -> str:
    """Convert seconds to HH:MM:SS.mmm timestamp format."""
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    milliseconds = int((seconds % 1) * 1000)  # Extract fractional seconds as milliseconds
    seconds = int(seconds)  # Get the integer part of seconds
    return f"{int(hours):02d}:{int(minutes):02d}:{seconds:02d}.{milliseconds:03d}"
