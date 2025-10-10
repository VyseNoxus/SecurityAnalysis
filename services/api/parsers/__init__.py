"""Parsers registry for supported log sources."""

from .zeek import parse_line as parse_zeek
from .windows import parse_line as parse_windows
from .cloudtrail import parse_line as parse_cloudtrail

# convenient lookup used by /ingest
PARSERS = {
    "zeek": parse_zeek,
    "windows": parse_windows,
    "cloudtrail": parse_cloudtrail,
}

__all__ = ["parse_zeek", "parse_windows", "parse_cloudtrail", "PARSERS"]
