import math
from collections import Counter, defaultdict
from typing import Any, Dict, List
import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR

def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not text:
        return 0.0
    freq = Counter(text.lower())
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def analyze_dns_forensics(
    pcap_path: str,
    entropy_threshold: float = 3.6,
    subdomain_len_threshold: int = 25,
) -> Dict[str, Any]:
    """Inspect DNS queries for DGA (Domain Generation Algorithms) and tunneling.
    
    Args:
        pcap_path: Path to capture file.
        entropy_threshold: Shannon entropy threshold for flagging suspicious domains.
        subdomain_len_threshold: Subdomain length indicating possible exfiltration.
        
    Returns:
        Dict containing DNS statistics, flagged tunneling/DGA domains, top queries, and record types.
    """
    packets = scapy.rdpcap(pcap_path)
    
    queries = Counter()
    qtypes = Counter()
    rcode_counts = Counter()
    suspicious_queries = []
    seen_queries = set()
    large_payload_records = []
    
    for pkt in packets:
        if not pkt.haslayer(DNS):
            continue
        dns = pkt[DNS]
        
        # Responses / RCODE
        if dns.qr == 1:
            rcode_name = {
                0: "NOERROR",
                1: "FORMERR",
                2: "SERVFAIL",
                3: "NXDOMAIN",
                4: "NOTIMP",
                5: "REFUSED",
            }.get(dns.rcode, f"RCODE_{dns.rcode}")
            rcode_counts[rcode_name] += 1
            
            # Check answer records for large TXT/NULL
            if dns.ancount > 0 and dns.an:
                curr = dns.an
                for _ in range(dns.ancount):
                    if curr:
                        # TXT record (type 16) or NULL (type 10)
                        if curr.type in [10, 16] and hasattr(curr, "rdata"):
                            rdata_str = str(curr.rdata)
                            if len(rdata_str) > 120:
                                large_payload_records.append({
                                    "name": curr.rrname.decode("utf-8", "ignore") if hasattr(curr.rrname, "decode") else str(curr.rrname),
                                    "type": "TXT" if curr.type == 16 else "NULL",
                                    "length_bytes": len(rdata_str),
                                    "sample_data": rdata_str[:80] + "..." if len(rdata_str) > 80 else rdata_str,
                                })
                        curr = curr.payload if hasattr(curr, "payload") else None

        # Queries
        if dns.qdcount > 0 and dns.qd:
            qname = dns.qd.qname
            if hasattr(qname, "decode"):
                qname_str = qname.decode("utf-8", "ignore").rstrip(".")
            else:
                qname_str = str(qname).rstrip(".")
                
            qtype = dns.qd.qtype
            qtype_name = {
                1: "A", 28: "AAAA", 16: "TXT", 15: "MX", 2: "NS", 5: "CNAME", 10: "NULL", 12: "PTR"
            }.get(qtype, f"TYPE_{qtype}")
            
            queries[qname_str] += 1
            qtypes[qtype_name] += 1
            
            # Analyze domain entropy and subdomain length for potential DGA / Tunneling
            if qname_str not in seen_queries:
                seen_queries.add(qname_str)
                parts = qname_str.split(".")
                subdomain = ".".join(parts[:-2]) if len(parts) > 2 else (parts[0] if parts else "")
                
                domain_entropy = round(shannon_entropy(qname_str), 3)
                subdomain_entropy = round(shannon_entropy(subdomain), 3) if subdomain else 0.0
                
                is_suspicious = False
                reasons = []
                
                if subdomain_entropy >= entropy_threshold and len(subdomain) >= 12:
                    is_suspicious = True
                    reasons.append(f"High subdomain entropy ({subdomain_entropy})")
                
                if len(subdomain) >= subdomain_len_threshold:
                    is_suspicious = True
                    reasons.append(f"Excessive subdomain length ({len(subdomain)} chars)")
                
                if is_suspicious:
                    suspicious_queries.append({
                        "domain": qname_str,
                        "subdomain": subdomain,
                        "domain_entropy": domain_entropy,
                        "subdomain_entropy": subdomain_entropy,
                        "subdomain_length": len(subdomain),
                        "reasons": reasons,
                    })

    # Sort suspicious queries by entropy descending
    suspicious_queries.sort(key=lambda x: x["subdomain_entropy"], reverse=True)

    return {
        "total_dns_queries": sum(queries.values()),
        "unique_domains": len(queries),
        "response_codes": dict(rcode_counts),
        "nxdomain_count": rcode_counts.get("NXDOMAIN", 0),
        "record_types": dict(qtypes),
        "suspicious_dns_tunneling_or_dga_count": len(suspicious_queries),
        "flagged_domains": suspicious_queries[:30],
        "top_queried_domains": [
            {"domain": dom, "count": count}
            for dom, count in queries.most_common(15)
        ],
        "large_txt_null_records": large_payload_records[:10],
    }
