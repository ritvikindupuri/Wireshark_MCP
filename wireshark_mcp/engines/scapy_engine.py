import os
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS

class ScapyEngine:
    """Pure Python packet capture parser using Scapy."""

    @staticmethod
    def get_pcap_overview(pcap_path: str) -> Dict[str, Any]:
        """Read summary stats, packet counts, protocol distribution, and duration."""
        if not os.path.isfile(pcap_path):
            raise FileNotFoundError(f"Capture file not found: {pcap_path}")

        file_size = os.path.getsize(pcap_path)
        packets = scapy.rdpcap(pcap_path)

        total_packets = len(packets)
        if total_packets == 0:
            return {
                "file_path": pcap_path,
                "file_size_bytes": file_size,
                "total_packets": 0,
                "duration_seconds": 0.0,
                "protocols": {},
                "start_time": None,
                "end_time": None,
            }

        start_time = float(packets[0].time)
        end_time = float(packets[-1].time)
        duration = max(0.0, end_time - start_time)

        proto_counts = Counter()
        for pkt in packets:
            if pkt.haslayer(TCP):
                proto_counts["TCP"] += 1
            elif pkt.haslayer(UDP):
                proto_counts["UDP"] += 1
            elif pkt.haslayer(ICMP):
                proto_counts["ICMP"] += 1
            elif pkt.haslayer(ARP):
                proto_counts["ARP"] += 1
            elif pkt.haslayer(IPv6):
                proto_counts["IPv6"] += 1
            elif pkt.haslayer(IP):
                proto_counts["IPv4 (Other)"] += 1
            else:
                proto_counts["Other"] += 1

            if pkt.haslayer(DNS):
                proto_counts["DNS"] += 1
            if pkt.haslayer(scapy.Raw):
                payload = bytes(pkt[scapy.Raw].load)
                if payload.startswith(b"HTTP/") or any(
                    payload.startswith(m) for m in [b"GET ", b"POST ", b"PUT ", b"HEAD "]
                ):
                    proto_counts["HTTP"] += 1
                elif len(payload) > 5 and payload[0] == 0x16 and payload[1:3] in [b"\x03\x01", b"\x03\x02", b"\x03\x03"]:
                    proto_counts["TLS"] += 1

        return {
            "file_path": pcap_path,
            "file_size_bytes": file_size,
            "file_size_formatted": f"{file_size / (1024 * 1024):.2f} MB" if file_size > 1024*1024 else f"{file_size / 1024:.2f} KB",
            "total_packets": total_packets,
            "duration_seconds": round(duration, 3),
            "start_time": datetime.fromtimestamp(start_time).isoformat() if start_time else None,
            "end_time": datetime.fromtimestamp(end_time).isoformat() if end_time else None,
            "protocol_breakdown": dict(proto_counts.most_common()),
        }

    @staticmethod
    def list_conversations(pcap_path: str, conv_type: str = "ip") -> List[Dict[str, Any]]:
        """Extract top conversations (IP or TCP/UDP flows)."""
        packets = scapy.rdpcap(pcap_path)
        flows = defaultdict(lambda: {"packets": 0, "bytes": 0, "first_seen": None, "last_seen": None})

        for pkt in packets:
            pkt_time = float(pkt.time)
            pkt_len = len(pkt)

            src, dst = None, None
            if conv_type == "ip":
                if pkt.haslayer(IP):
                    src, dst = pkt[IP].src, pkt[IP].dst
                elif pkt.haslayer(IPv6):
                    src, dst = pkt[IPv6].src, pkt[IPv6].dst
            elif conv_type in ["tcp", "udp"]:
                layer = TCP if conv_type == "tcp" else UDP
                if pkt.haslayer(IP) and pkt.haslayer(layer):
                    src = f"{pkt[IP].src}:{pkt[layer].sport}"
                    dst = f"{pkt[IP].dst}:{pkt[layer].dport}"
                elif pkt.haslayer(IPv6) and pkt.haslayer(layer):
                    src = f"[{pkt[IPv6].src}]:{pkt[layer].sport}"
                    dst = f"[{pkt[IPv6].dst}]:{pkt[layer].dport}"

            if not src or not dst:
                continue

            # Canonical order for bidirectional pairing
            pair = tuple(sorted([src, dst]))
            stat = flows[pair]
            stat["packets"] += 1
            stat["bytes"] += pkt_len
            if stat["first_seen"] is None or pkt_time < stat["first_seen"]:
                stat["first_seen"] = pkt_time
            if stat["last_seen"] is None or pkt_time > stat["last_seen"]:
                stat["last_seen"] = pkt_time

        result = []
        for (ep1, ep2), data in flows.items():
            dur = max(0.0, data["last_seen"] - data["first_seen"]) if data["last_seen"] and data["first_seen"] else 0.0
            result.append({
                "endpoint_a": ep1,
                "endpoint_b": ep2,
                "total_packets": data["packets"],
                "total_bytes": data["bytes"],
                "duration_seconds": round(dur, 3),
            })

        # Sort by total bytes transferred descending
        result.sort(key=lambda x: x["total_bytes"], reverse=True)
        return result
