"""Normalize Windows Event logs (e.g., Event ID 4104, 4688) to a common schema."""

from typing import Dict, Any

def parse_line(line: Dict[str, Any]) -> Dict[str, Any]:
    ts = line.get("TimeCreated") or line.get("@timestamp")
    src = line.get("IpAddress") or line.get("SourceIp") or line.get("SourceNetworkAddress")
    dst = line.get("DestIp") or line.get("DestinationIp")
    eid = line.get("EventID") or line.get("EventId") or line.get("EventID.code")

    # Prefer the verbose description fields if present
    message = (
        line.get("Message")
        or line.get("RenderedDescription")
        or line.get("Details")
        or ""
    )
    # Trim very long messages to avoid huge vectors
    message = message[:2000]

    return {
        "timestamp": ts,
        "src_ip": src,
        "dst_ip": dst,
        "event_type": f"win:{eid}" if eid is not None else "win",
        "message": message,
        "raw": line,
    }
