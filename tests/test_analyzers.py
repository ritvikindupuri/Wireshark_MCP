import os
import pytest
from wireshark_mcp.analyzers.dns import analyze_dns_forensics, shannon_entropy
from wireshark_mcp.analyzers.heuristics import scan_threat_indicators
from wireshark_mcp.analyzers.streams import reassemble_stream
from wireshark_mcp.analyzers.tls import analyze_tls_fingerprints
from wireshark_mcp.engines.scapy_engine import ScapyEngine
from tests.generate_sample_pcap import create_sample_pcap

@pytest.fixture(scope="session")
def sample_pcap(tmp_path_factory):
    fn = tmp_path_factory.mktemp("data") / "sample.pcap"
    create_sample_pcap(str(fn))
    return str(fn)

def test_shannon_entropy():
    # Regular domain
    e1 = shannon_entropy("google.com")
    # High entropy base64 string
    e2 = shannon_entropy("dGhpc2lzdGVzdGRuc3R1bm5lbGluZ2RhdGFleGZpbHRyYXRpb24")
    assert e2 > e1
    assert e2 > 3.5

def test_pcap_overview(sample_pcap):
    overview = ScapyEngine.get_pcap_overview(sample_pcap)
    assert overview["total_packets"] > 30
    assert overview["duration_seconds"] > 0
    assert "DNS" in overview["protocol_breakdown"]
    assert "TCP" in overview["protocol_breakdown"]

def test_list_conversations(sample_pcap):
    convs = ScapyEngine.list_conversations(sample_pcap, conv_type="ip")
    assert len(convs) >= 4
    assert any("192.168.1.50" in c["endpoint_a"] or "192.168.1.50" in c["endpoint_b"] for c in convs)

def test_dns_forensics(sample_pcap):
    dns_res = analyze_dns_forensics(sample_pcap)
    assert dns_res["total_dns_queries"] >= 2
    assert dns_res["nxdomain_count"] >= 1
    # Check that high entropy tunneling query was flagged
    assert dns_res["suspicious_dns_tunneling_or_dga_count"] >= 1
    flagged_domains = [f["domain"] for f in dns_res["flagged_domains"]]
    assert any("tunnel" in d for d in flagged_domains)

def test_tls_fingerprints(sample_pcap):
    tls_res = analyze_tls_fingerprints(sample_pcap)
    assert tls_res["total_tls_handshakes"] >= 1
    assert len(tls_res["top_ja3_fingerprints"]) >= 1
    # SNI check
    assert any(s["sni"] == "c2.darknet-operation.com" for s in tls_res["top_snis"])

def test_heuristics_credentials_and_recon(sample_pcap):
    threat_res = scan_threat_indicators(sample_pcap)
    assert threat_res["total_findings"] >= 3
    
    # Check HTTP Basic Auth detection
    details = [f["detail"] for f in threat_res["findings"]]
    assert any("admin:SuperSecretPass!" in d for d in details)
    # Check FTP Credential detection
    assert any("Spring2026!Secure" in d for d in details)
    # Check Port Scan detection
    assert any("probed" in d and "ports" in d for d in details)
    # Check Beaconing detection
    assert len(threat_res["potential_c2_beaconing"]) >= 1
    assert threat_res["potential_c2_beaconing"][0]["src"] == "192.168.1.120"

def test_stream_reassembly(sample_pcap):
    # Find HTTP stream
    stream_res = reassemble_stream(sample_pcap, stream_index=0)
    assert "stream_content" in stream_res
    assert stream_res["total_packets_in_stream"] >= 1
