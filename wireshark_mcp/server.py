"""Wireshark & PCAP Threat Triage MCP Server for Security Engineers."""

import json
import os
from typing import Any, Dict, List, Optional
from mcp.server.fastmcp import FastMCP

from wireshark_mcp.analyzers.dns import analyze_dns_forensics
from wireshark_mcp.analyzers.heuristics import scan_threat_indicators
from wireshark_mcp.analyzers.streams import reassemble_stream
from wireshark_mcp.analyzers.tls import analyze_tls_fingerprints
from wireshark_mcp.engines.detector import find_tshark, is_tshark_available
from wireshark_mcp.engines.scapy_engine import ScapyEngine
from wireshark_mcp.engines.tshark_engine import TsharkEngine

# Initialize FastMCP application
mcp = FastMCP("wireshark-mcp")

# Directory for storing uploaded PCAP files
UPLOAD_DIR = os.path.join(os.environ.get("TEMP", "."), "wireshark_mcp_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


@mcp.tool()
def get_engine_status() -> Dict[str, Any]:
    """Check the status of packet analysis engines (TShark & Scapy).
    
    Returns whether the official Wireshark tshark binary is discovered and available,
    the binary path, and supported analysis features.
    """
    tshark_path = find_tshark()
    return {
        "tshark_available": tshark_path is not None,
        "tshark_path": tshark_path,
        "scapy_engine_available": True,
        "capabilities": [
            "PCAP & PCAPNG Metadata & Protocol Breakdown",
            "Conversation Summaries (IP, TCP, UDP)",
            "Wireshark Native Display Filtering (TShark when available)",
            "DNS Entropy, DGA & Tunneling Exfiltration Detection",
            "TLS SNI Extraction & JA3 Fingerprinting",
            "Cleartext Credential Hunting (HTTP Auth, FTP, Telnet, POST data)",
            "Port Scan & TCP SYN Anomaly Detection",
            "C2 Beaconing Timing & Low-Jitter Flow Analysis",
            "TCP & UDP Stream Reassembly",
        ],
    }


@mcp.tool()
def pcap_overview(file_path: str) -> Dict[str, Any]:
    """Inspect capture metadata, duration, total packet count, and protocol breakdown.
    
    Args:
        file_path: Absolute path to the .pcap or .pcapng file.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    # Use Scapy engine for fast, structured breakdown
    overview = ScapyEngine.get_pcap_overview(file_path)

    # If tshark is available, also attach native protocol hierarchy tree
    if is_tshark_available():
        try:
            tshark = TsharkEngine()
            overview["tshark_protocol_hierarchy"] = tshark.get_protocol_hierarchy(file_path)
        except Exception:
            pass

    return overview


@mcp.tool()
def list_conversations(file_path: str, protocol: str = "ip") -> Dict[str, Any]:
    """List and rank top network conversations by volume and packet count.
    
    Args:
        file_path: Absolute path to the .pcap or .pcapng file.
        protocol: Conversation type to aggregate: 'ip', 'tcp', or 'udp'.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    convs = ScapyEngine.list_conversations(file_path, conv_type=protocol.lower())
    return {
        "file_path": file_path,
        "protocol": protocol.upper(),
        "total_conversations": len(convs),
        "conversations": convs[:50],  # Return top 50 to fit LLM context
    }


@mcp.tool()
def apply_display_filter(
    file_path: str,
    display_filter: str,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    """Execute a Wireshark display filter against a packet capture.
    
    Examples of display_filter:
    - 'http.request.method == "POST"'
    - 'tcp.flags.syn == 1 and tcp.flags.ack == 0'
    - 'dns.flags.response == 1'
    - 'tls.handshake.type == 1'
    - 'ip.addr == 192.168.1.5'
    
    Args:
        file_path: Absolute path to the .pcap or .pcapng file.
        display_filter: Valid Wireshark display filter expression.
        limit: Maximum number of packets to return (pagination, default 50).
        offset: Zero-based starting index for pagination (default 0).
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    if is_tshark_available():
        tshark = TsharkEngine()
        return tshark.apply_filter(
            pcap_path=file_path,
            display_filter=display_filter,
            limit=limit,
            offset=offset,
        )
    else:
        return {
            "error": "TShark executable not found. Native display filter execution requires Wireshark/tshark to be installed.",
            "suggestion": "Install Wireshark or use specialized forensic tools: extract_dns_forensics, extract_tls_fingerprints, scan_suspicious_indicators.",
        }


@mcp.tool()
def extract_dns_forensics(
    file_path: str,
    entropy_threshold: float = 3.6,
    subdomain_len_threshold: int = 25,
) -> Dict[str, Any]:
    """Inspect DNS queries for DGA (Domain Generation Algorithms) and DNS tunneling exfiltration.
    
    Computes Shannon entropy on domains/subdomains, flags high NXDOMAIN responses,
    extracts large TXT/NULL records, and lists top queried domains.
    
    Args:
        file_path: Absolute path to the .pcap or .pcapng file.
        entropy_threshold: Shannon entropy cut-off (default 3.6).
        subdomain_len_threshold: Subdomain length cut-off (default 25 chars).
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    return analyze_dns_forensics(
        pcap_path=file_path,
        entropy_threshold=entropy_threshold,
        subdomain_len_threshold=subdomain_len_threshold,
    )


@mcp.tool()
def extract_tls_fingerprints(file_path: str) -> Dict[str, Any]:
    """Extract TLS ClientHellos, calculate JA3 client fingerprints, and map SNIs.
    
    Useful for identifying malicious C2 frameworks, anomalous client software,
    and unencrypted SNI hostnames.
    
    Args:
        file_path: Absolute path to the .pcap or .pcapng file.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    return analyze_tls_fingerprints(pcap_path=file_path)


@mcp.tool()
def scan_suspicious_indicators(file_path: str) -> Dict[str, Any]:
    """Run automated threat hunting heuristics across the packet capture.
    
    Checks for:
    - Cleartext credentials (HTTP Basic Auth base64 decoding, FTP USER/PASS, Telnet, POST parameters)
    - Port scanning and TCP SYN floods
    - Persistent C2 beaconing (low-jitter timing intervals)
    
    Args:
        file_path: Absolute path to the .pcap or .pcapng file.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    return scan_threat_indicators(pcap_path=file_path)


@mcp.tool()
def follow_stream(
    file_path: str,
    stream_index: int = 0,
    protocol: str = "tcp",
    max_payload_bytes: int = 65536,
) -> Dict[str, Any]:
    """Reconstruct and extract conversational payload from a TCP or UDP stream.
    
    Args:
        file_path: Absolute path to the .pcap or .pcapng file.
        stream_index: Zero-based stream index.
        protocol: 'tcp' or 'udp' (default 'tcp').
        max_payload_bytes: Limit payload size to avoid overwhelming context (default 64KB).
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    # Use native stream reassembly
    return reassemble_stream(
        pcap_path=file_path,
        stream_index=stream_index,
        protocol=protocol,
        max_payload_bytes=max_payload_bytes,
    )


@mcp.tool()
def upload_pcap(base64_data: str, filename: Optional[str] = None) -> Dict[str, Any]:
    """Upload a PCAP file directly into the MCP server as a Base64-encoded string.
    
    This allows web-based AI clients or chat interfaces without direct local filesystem
    access to upload packet captures directly.
    
    Args:
        base64_data: Base64-encoded binary contents of the .pcap or .pcapng file.
        filename: Optional suggested filename (e.g. 'incident_capture.pcap').
        
    Returns:
        Dict with status, assigned server file path, file size, and quick overview.
    """
    import base64
    
    # 1. DoS Protection: Limit base64 input string length (max ~50MB payload)
    MAX_UPLOAD_BYTES = 50 * 1024 * 1024
    if len(base64_data) > MAX_UPLOAD_BYTES * 1.4:
        return {"error": f"Upload payload too large. Maximum size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB"}

    try:
        raw_bytes = base64.b64decode(base64_data)
    except Exception as e:
        return {"error": f"Failed to decode base64 data: {str(e)}"}

    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        return {"error": f"Upload file size exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit"}

    # 2. Path Traversal Protection: Sanitize filename using basename and alphanumeric characters
    if filename:
        clean_name = os.path.basename(filename).replace("..", "").replace("/", "").replace("\\", "")
        clean_name = "".join(c for c in clean_name if c.isalnum() or c in "._-")
        if not clean_name:
            clean_name = f"upload_{os.urandom(4).hex()}.pcap"
    else:
        clean_name = f"upload_{os.urandom(4).hex()}.pcap"

    if not (clean_name.endswith(".pcap") or clean_name.endswith(".pcapng") or clean_name.endswith(".cap")):
        clean_name += ".pcap"

    target_path = os.path.abspath(os.path.join(UPLOAD_DIR, clean_name))

    # Ensure target_path stays strictly inside UPLOAD_DIR
    if not target_path.startswith(os.path.abspath(UPLOAD_DIR)):
        return {"error": "Invalid target upload path"}

    with open(target_path, "wb") as f:
        f.write(raw_bytes)

    overview = pcap_overview(target_path)

    return {
        "status": "success",
        "message": f"PCAP uploaded successfully ({len(raw_bytes)} bytes)",
        "file_path": target_path,
        "filename": clean_name,
        "quick_overview": overview,
    }


@mcp.tool()
def analyze_uploaded_pcap(
    base64_data: str,
    filename: Optional[str] = None,
) -> Dict[str, Any]:
    """Upload and run an all-in-one comprehensive forensic triage in a single step.
    
    Args:
        base64_data: Base64-encoded binary contents of the .pcap or .pcapng file.
        filename: Optional filename.
        
    Returns:
        Full triage report: overview, threat findings, DNS forensics, and TLS fingerprints.
    """
    upload_res = upload_pcap(base64_data=base64_data, filename=filename)
    if "error" in upload_res:
        return upload_res

    target_path = upload_res["file_path"]

    return {
        "file_path": target_path,
        "filename": upload_res["filename"],
        "overview": upload_res["quick_overview"],
        "conversations": list_conversations(file_path=target_path, protocol="ip"),
        "threat_findings": scan_suspicious_indicators(file_path=target_path),
        "dns_forensics": extract_dns_forensics(file_path=target_path),
        "tls_fingerprints": extract_tls_fingerprints(file_path=target_path),
    }


def main():
    """Run the MCP server via stdio transport."""
    mcp.run()


if __name__ == "__main__":
    main()
