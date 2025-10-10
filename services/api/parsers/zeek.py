"""Normalize Zeek connection-style records to a common schema."""

from typing import Dict, Any

def parse_line(line: Dict[str, Any]) -> Dict[str, Any]:
    # Accept both Zeek JSON and pre-normalized keys.
    ts = line.get("ts") or line.get("timestamp")
    src = line.get("id.orig_h") or line.get("src_ip")
    dst = line.get("id.resp_h") or line.get("dst_ip")
    proto = line.get("proto")
    service = line.get("service")

    # Short, human-readable message for embedding and display
    parts = [line.get("uid"), src, dst, proto, service]
    msg = " ".join(str(x) for x in parts if x)

    return {
        "timestamp": ts,
        "src_ip": src,
        "dst_ip": dst,
        "event_type": proto or "zeek",
        "message": msg,
        "raw": line,  # keep original for traceability
    }
