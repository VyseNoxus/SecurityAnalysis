"""Normalize AWS CloudTrail events to a common schema."""

from typing import Dict, Any

def parse_line(line: Dict[str, Any]) -> Dict[str, Any]:
    event = line.get("eventName") or line.get("event_name")
    who = (line.get("userIdentity") or {}).get("arn") or (line.get("userIdentity") or {}).get("userName") or "unknown"
    ts = line.get("eventTime") or line.get("event_time")
    src_ip = line.get("sourceIPAddress") or line.get("sourceIpAddress")

    message = f"{event} by {who}" if event else f"cloudtrail event by {who}"

    return {
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": None,
        "event_type": f"aws:{event}" if event else "aws",
        "message": message,
        "raw": line,
    }
