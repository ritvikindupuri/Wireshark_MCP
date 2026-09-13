import pytest
from wireshark_mcp.server import (
    get_engine_status,
    pcap_overview,
    list_conversations,
    extract_dns_forensics,
    extract_tls_fingerprints,
    scan_suspicious_indicators,
    follow_stream,
    upload_pcap,
    analyze_uploaded_pcap,
)
from tests.generate_sample_pcap import create_sample_pcap

@pytest.fixture(scope="session")
def sample_pcap(tmp_path_factory):
    fn = tmp_path_factory.mktemp("data") / "sample.pcap"
    create_sample_pcap(str(fn))
    return str(fn)

def test_mcp_get_engine_status():
    status = get_engine_status()
    assert "capabilities" in status
    assert len(status["capabilities"]) >= 5

def test_mcp_pcap_overview(sample_pcap):
    res = pcap_overview(sample_pcap)
    assert res["total_packets"] > 0
    assert "protocol_breakdown" in res

def test_mcp_list_conversations(sample_pcap):
    res = list_conversations(sample_pcap, protocol="ip")
    assert res["total_conversations"] > 0
    assert "conversations" in res

def test_mcp_extract_dns_forensics(sample_pcap):
    res = extract_dns_forensics(sample_pcap)
    assert res["total_dns_queries"] > 0

def test_mcp_extract_tls_fingerprints(sample_pcap):
    res = extract_tls_fingerprints(sample_pcap)
    assert res["total_tls_handshakes"] > 0

def test_mcp_scan_suspicious_indicators(sample_pcap):
    res = scan_suspicious_indicators(sample_pcap)
    assert res["total_findings"] > 0

def test_mcp_follow_stream(sample_pcap):
    res = follow_stream(sample_pcap, stream_index=0)
    assert "stream_content" in res

def test_mcp_upload_pcap(sample_pcap):
    import base64
    import os

    with open(sample_pcap, "rb") as f:
        b64 = base64.b64encode(f.read()).decode("ascii")

    res = upload_pcap(base64_data=b64, filename="test_upload.pcap")
    assert res["status"] == "success"
    assert "file_path" in res
    assert os.path.exists(res["file_path"])

    triage_res = analyze_uploaded_pcap(base64_data=b64, filename="test_upload_triage.pcap")
    assert "overview" in triage_res
    assert "threat_findings" in triage_res
