import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from wireshark_mcp.engines.detector import find_tshark

class TsharkEngine:
    """Wrapper for executing tshark CLI commands with safety limits."""

    def __init__(self, tshark_bin: Optional[str] = None):
        self.tshark_bin = tshark_bin or find_tshark()
        if not self.tshark_bin:
            raise RuntimeError(
                "tshark binary not found. Please install Wireshark or set TSHARK_PATH."
            )

    def run_cmd(self, args: List[str], timeout_sec: int = 30) -> str:
        """Run a raw tshark command and return stdout."""
        cmd = [self.tshark_bin] + args
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
        )
        if res.returncode != 0 and res.stderr:
            # Note: tshark sometimes writes harmless warnings to stderr
            if not res.stdout.strip():
                raise RuntimeError(f"tshark failed: {res.stderr.strip()}")
        return res.stdout

    def get_protocol_hierarchy(self, pcap_path: str) -> str:
        """Get protocol hierarchy statistics (-qz io,phs)."""
        output = self.run_cmd(["-r", pcap_path, "-qz", "io,phs", "-n"])
        # Extract the portion between separator lines
        lines = output.splitlines()
        start = False
        res = []
        for line in lines:
            if "Protocol Hierarchy Statistics" in line or "Filter:" in line:
                start = True
            if start:
                res.append(line)
        return "\n".join(res) if res else output

    def get_conversations(self, pcap_path: str, conv_type: str = "ip") -> str:
        """Get conversations table (-qz conv,<type>)."""
        valid_types = ["ip", "ipv6", "tcp", "udp", "eth"]
        if conv_type not in valid_types:
            conv_type = "ip"
        output = self.run_cmd(["-r", pcap_path, "-qz", f"conv,{conv_type}", "-n"])
        return output

    def apply_filter(
        self,
        pcap_path: str,
        display_filter: str,
        limit: int = 50,
        offset: int = 0,
        fields: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Apply a Wireshark display filter and return structured packet info."""
        if not fields:
            fields = [
                "_ws.col.No.",
                "_ws.col.Time",
                "_ws.col.Source",
                "_ws.col.Destination",
                "_ws.col.Protocol",
                "_ws.col.Length",
                "_ws.col.Info",
            ]

        # Use tshark -T json or -T fields
        args = ["-r", pcap_path, "-n"]
        if display_filter:
            args.extend(["-Y", display_filter])

        # Fetch with fields formatting for compact JSON
        args.extend(["-T", "fields"])
        for f in fields:
            args.extend(["-e", f])
        args.extend(["-E", "header=y", "-E", "separator=/t", "-E", "occurrence=f"])

        raw_out = self.run_cmd(args, timeout_sec=45)
        lines = [l.strip() for l in raw_out.splitlines() if l.strip()]

        if not lines:
            return {"total_matches": 0, "packets": []}

        headers = [h.replace("_ws.col.", "").lower() for h in lines[0].split("\t")]
        all_rows = lines[1:]
        total = len(all_rows)

        # Slice pagination
        paginated_rows = all_rows[offset : offset + limit]
        packets = []
        for row in paginated_rows:
            vals = row.split("\t")
            # Pad missing values if any
            while len(vals) < len(headers):
                vals.append("")
            packets.append(dict(zip(headers, vals)))

        return {
            "total_matches": total,
            "returned_count": len(packets),
            "offset": offset,
            "limit": limit,
            "has_more": (offset + len(packets)) < total,
            "packets": packets,
        }

    def follow_stream(self, pcap_path: str, stream_id: int, protocol: str = "tcp") -> str:
        """Follow TCP/UDP/TLS stream payload."""
        proto_flag = f"{protocol},ascii,{stream_id}"
        output = self.run_cmd(["-r", pcap_path, "-qz", f"follow,{proto_flag}", "-n"])
        return output
