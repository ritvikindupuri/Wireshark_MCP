import hashlib
import struct
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
import scapy.all as scapy
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6

# GREASE values defined in RFC 8701 to filter out when computing JA3
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
    0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBAAB,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA
}

def parse_client_hello(payload: bytes) -> Optional[Dict[str, Any]]:
    """Parse TLS ClientHello raw bytes and extract fields for JA3 and SNI."""
    try:
        # TLS Record Header: Type (1 byte) = 0x16 (Handshake), Version (2 bytes), Length (2 bytes)
        if len(payload) < 9 or payload[0] != 0x16:
            return None
        
        record_version = struct.unpack("!H", payload[1:3])[0]
        handshake_type = payload[5]
        if handshake_type != 1:  # ClientHello
            return None

        # Handshake version
        client_version = struct.unpack("!H", payload[9:11])[0]
        
        # Session ID length and skip
        idx = 43  # 5 (record) + 4 (handshake header) + 2 (version) + 32 (random)
        if len(payload) < idx + 1:
            return None
        session_id_len = payload[idx]
        idx += 1 + session_id_len

        # Cipher Suites
        if len(payload) < idx + 2:
            return None
        cipher_len = struct.unpack("!H", payload[idx:idx+2])[0]
        idx += 2
        
        ciphers = []
        for i in range(0, cipher_len, 2):
            if idx + i + 2 > len(payload):
                break
            c = struct.unpack("!H", payload[idx+i:idx+i+2])[0]
            if c not in GREASE_VALUES:
                ciphers.append(c)
        idx += cipher_len

        # Compression Methods
        if len(payload) < idx + 1:
            return None
        comp_len = payload[idx]
        idx += 1 + comp_len

        # Extensions
        extensions = []
        elliptic_curves = []
        ec_point_formats = []
        sni = None

        if len(payload) >= idx + 2:
            ext_total_len = struct.unpack("!H", payload[idx:idx+2])[0]
            idx += 2
            ext_end = idx + ext_total_len

            while idx + 4 <= min(len(payload), ext_end):
                ext_type, ext_len = struct.unpack("!HH", payload[idx:idx+4])
                idx += 4
                ext_data = payload[idx:idx+ext_len]
                idx += ext_len

                if ext_type not in GREASE_VALUES:
                    extensions.append(ext_type)

                # SNI (Extension Type 0)
                if ext_type == 0 and len(ext_data) > 5:
                    # list_len (2), name_type (1) = 0 (host_name), name_len (2)
                    name_len = struct.unpack("!H", ext_data[3:5])[0]
                    if len(ext_data) >= 5 + name_len:
                        sni = ext_data[5:5+name_len].decode("utf-8", "ignore")

                # Supported Groups / Elliptic Curves (Extension Type 10 / 0x000a)
                elif ext_type == 10 and len(ext_data) >= 2:
                    curves_len = struct.unpack("!H", ext_data[0:2])[0]
                    for i in range(2, min(len(ext_data), 2 + curves_len), 2):
                        curve = struct.unpack("!H", ext_data[i:i+2])[0]
                        if curve not in GREASE_VALUES:
                            elliptic_curves.append(curve)

                # EC Point Formats (Extension Type 11 / 0x000b)
                elif ext_type == 11 and len(ext_data) >= 1:
                    fmt_len = ext_data[0]
                    for i in range(1, min(len(ext_data), 1 + fmt_len)):
                        ec_point_formats.append(ext_data[i])

        # JA3 String: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        ja3_raw = "-".join([
            str(client_version),
            "-".join(map(str, ciphers)),
            "-".join(map(str, extensions)),
            "-".join(map(str, elliptic_curves)),
            "-".join(map(str, ec_point_formats)),
        ])
        ja3_hash = hashlib.md5(ja3_raw.encode("ascii", "ignore")).hexdigest()

        return {
            "version": hex(client_version),
            "sni": sni,
            "ja3_string": ja3_raw,
            "ja3_hash": ja3_hash,
            "ciphers_count": len(ciphers),
            "extensions_count": len(extensions),
        }
    except Exception:
        return None

def analyze_tls_fingerprints(pcap_path: str) -> Dict[str, Any]:
    """Extract TLS Client Hellos, calculate JA3 fingerprints, and map SNIs.
    
    Args:
        pcap_path: Path to capture file.
        
    Returns:
        Dict containing JA3 hashes, SNIs, client IP mappings, and anomaly summary.
    """
    packets = scapy.rdpcap(pcap_path)
    
    ja3_counts = Counter()
    sni_counts = Counter()
    clients = []
    
    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(scapy.Raw):
            continue
        
        raw_payload = bytes(pkt[scapy.Raw].load)
        info = parse_client_hello(raw_payload)
        if not info:
            continue
            
        src_ip = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "unknown")
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else "unknown")
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        
        ja3_hash = info["ja3_hash"]
        sni = info["sni"] or "(no SNI / IP connection)"
        
        ja3_counts[ja3_hash] += 1
        sni_counts[sni] += 1
        
        clients.append({
            "timestamp": float(pkt.time),
            "src": f"{src_ip}:{src_port}",
            "dst": f"{dst_ip}:{dst_port}",
            "sni": sni,
            "ja3_hash": ja3_hash,
            "tls_version": info["version"],
        })
        
    return {
        "total_tls_handshakes": len(clients),
        "unique_ja3_fingerprints": len(ja3_counts),
        "unique_snis": len(sni_counts),
        "top_ja3_fingerprints": [
            {"ja3_hash": h, "count": cnt} for h, cnt in ja3_counts.most_common(10)
        ],
        "top_snis": [
            {"sni": s, "count": cnt} for s, cnt in sni_counts.most_common(10)
        ],
        "handshakes": clients[:50],
    }
