import base64
import re
from collections import defaultdict
from typing import Any, Dict, List
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

AUTH_BASIC_REGEX = re.compile(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
HTTP_CRED_PARAMS_REGEX = re.compile(
    r"(?:password|passwd|pass|pwd|api_key|apikey|secret|token)=([^&\s]+)", re.IGNORECASE
)
FTP_USER_REGEX = re.compile(r"^USER\s+(.+)$", re.IGNORECASE | re.MULTILINE)
FTP_PASS_REGEX = re.compile(r"^PASS\s+(.+)$", re.IGNORECASE | re.MULTILINE)

def scan_threat_indicators(pcap_path: str) -> Dict[str, Any]:
    """Scan PCAP for high-confidence security anomalies and credential exposure."""
    packets = scapy.rdpcap(pcap_path)
    
    findings = []
    syn_counts = defaultdict(lambda: {"dst_ports": set(), "dst_ips": set(), "count": 0})
    flow_timestamps = defaultdict(list)
    
    for idx, pkt in enumerate(packets):
        pkt_time = float(pkt.time)
        src_ip = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else None)
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else None)

        # 1. Port scan heuristic: SYN without ACK
        if pkt.haslayer(TCP) and src_ip and dst_ip:
            flags = pkt[TCP].flags
            if flags == "S" or flags == 0x02:  # SYN only
                syn_counts[src_ip]["dst_ports"].add(pkt[TCP].dport)
                syn_counts[src_ip]["dst_ips"].add(dst_ip)
                syn_counts[src_ip]["count"] += 1

            # Flow tracking for beaconing
            flow_key = (src_ip, dst_ip, pkt[TCP].dport)
            flow_timestamps[flow_key].append(pkt_time)

        # 2. Inspect Raw payload for cleartext credentials
        if pkt.haslayer(scapy.Raw) and src_ip and dst_ip:
            try:
                payload = pkt[scapy.Raw].load.decode("utf-8", "ignore")
                
                # Check HTTP Basic Auth
                for match in AUTH_BASIC_REGEX.finditer(payload):
                    b64_cred = match.group(1)
                    try:
                        decoded = base64.b64decode(b64_cred).decode("utf-8", "ignore")
                        findings.append({
                            "category": "Cleartext Credentials",
                            "severity": "HIGH",
                            "protocol": "HTTP",
                            "src": src_ip,
                            "dst": dst_ip,
                            "packet_index": idx + 1,
                            "detail": f"Decoded HTTP Basic Auth credentials: '{decoded}'",
                        })
                    except Exception:
                        pass

                # Check HTTP POST passwords/keys
                if payload.startswith("POST ") or "POST /" in payload:
                    for match in HTTP_CRED_PARAMS_REGEX.finditer(payload):
                        findings.append({
                            "category": "Cleartext Credentials",
                            "severity": "MEDIUM",
                            "protocol": "HTTP POST",
                            "src": src_ip,
                            "dst": dst_ip,
                            "packet_index": idx + 1,
                            "detail": f"Plaintext credential/secret in HTTP body: '{match.group(0)}'",
                        })

                # Check FTP credentials
                for u_match in FTP_USER_REGEX.finditer(payload):
                    findings.append({
                        "category": "Cleartext Credentials",
                        "severity": "HIGH",
                        "protocol": "FTP",
                        "src": src_ip,
                        "dst": dst_ip,
                        "packet_index": idx + 1,
                        "detail": f"FTP plaintext user: '{u_match.group(1).strip()}'",
                    })
                for p_match in FTP_PASS_REGEX.finditer(payload):
                    findings.append({
                        "category": "Cleartext Credentials",
                        "severity": "CRITICAL",
                        "protocol": "FTP",
                        "src": src_ip,
                        "dst": dst_ip,
                        "packet_index": idx + 1,
                        "detail": f"FTP plaintext password: '{p_match.group(1).strip()}'",
                    })

                # Check Telnet cleartext login prompt
                if "login:" in payload.lower() or "password:" in payload.lower():
                    if pkt.haslayer(TCP) and (pkt[TCP].sport == 23 or pkt[TCP].dport == 23):
                        findings.append({
                            "category": "Insecure Protocol",
                            "severity": "MEDIUM",
                            "protocol": "Telnet",
                            "src": src_ip,
                            "dst": dst_ip,
                            "packet_index": idx + 1,
                            "detail": "Unencrypted Telnet session interaction observed",
                        })
            except Exception:
                pass

    # 3. Detect Port Scanners (e.g. > 15 distinct ports scanned from single IP)
    for scanner_ip, stats in syn_counts.items():
        if len(stats["dst_ports"]) >= 15:
            findings.append({
                "category": "Reconnaissance / Port Scan",
                "severity": "HIGH",
                "protocol": "TCP SYN",
                "src": scanner_ip,
                "dst": f"{len(stats['dst_ips'])} targets",
                "packet_index": 0,
                "detail": f"IP probed {len(stats['dst_ports'])} distinct ports across {stats['count']} SYN packets",
            })

    # 4. Beaconing detection (low variance in delta times)
    beaconing_flows = []
    for (src, dst, dport), ts_list in flow_timestamps.items():
        if len(ts_list) >= 8:
            deltas = [ts_list[i] - ts_list[i-1] for i in range(1, len(ts_list))]
            mean_delta = sum(deltas) / len(deltas)
            if mean_delta > 0.5:
                # Calculate variance
                variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
                std_dev = variance ** 0.5
                # If std_dev is very small relative to mean (< 20%), indicates rhythmic beaconing
                jitter_ratio = std_dev / mean_delta
                if jitter_ratio < 0.2:
                    beaconing_flows.append({
                        "src": src,
                        "dst": f"{dst}:{dport}",
                        "connection_count": len(ts_list),
                        "interval_mean_seconds": round(mean_delta, 2),
                        "jitter_ratio": round(jitter_ratio, 3),
                    })

    return {
        "total_findings": len(findings),
        "critical_severity_count": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high_severity_count": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium_severity_count": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "findings": findings,
        "potential_c2_beaconing": beaconing_flows,
    }
