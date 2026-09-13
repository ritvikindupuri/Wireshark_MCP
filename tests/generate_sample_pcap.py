import time
from pathlib import Path
import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

def create_sample_pcap(output_path: str) -> str:
    """Generate a synthetic PCAP containing various network events and security anomalies."""
    packets = []
    base_time = 1700000000.0

    # 1. Normal DNS Query & Response
    pkt1 = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=53210, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="www.example.com", qtype="A")
    )
    pkt1.time = base_time + 0.1
    packets.append(pkt1)

    pkt2 = Ether() / IP(src="8.8.8.8", dst="192.168.1.50") / UDP(sport=53, dport=53210) / DNS(
        qr=1, aa=1, rcode=0,
        qd=DNSQR(qname="www.example.com", qtype="A"),
        an=DNSRR(rrname="www.example.com", type="A", rdata="93.184.216.34", ttl=300)
    )
    pkt2.time = base_time + 0.2
    packets.append(pkt2)

    # 2. Malicious High-Entropy DNS Tunneling Query
    tunnel_domain = "dGhpc2lzdGVzdGRuc3R1bm5lbGluZ2RhdGFleGZpbHRyYXRpb24.tunnel.c2server.net"
    pkt3 = Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=54321, dport=53) / DNS(
        rd=1, qd=DNSQR(qname=tunnel_domain, qtype="TXT")
    )
    pkt3.time = base_time + 0.5
    packets.append(pkt3)

    # 3. DNS NXDOMAIN response
    pkt4 = Ether() / IP(src="8.8.8.8", dst="192.168.1.100") / UDP(sport=53, dport=54322) / DNS(
        qr=1, rcode=3,
        qd=DNSQR(qname="nonexistent-random-dga-domain192847.org", qtype="A")
    )
    pkt4.time = base_time + 0.7
    packets.append(pkt4)

    # 4. HTTP Basic Auth Cleartext Leak
    http_payload = (
        b"GET /admin/dashboard HTTP/1.1\r\n"
        b"Host: internal-portal.corp\r\n"
        b"Authorization: Basic YWRtaW46U3VwZXJTZWNyZXRQYXNzIQ==\r\n"
        b"User-Agent: Mozilla/5.0\r\n\r\n"
    )
    pkt5 = Ether() / IP(src="192.168.1.50", dst="10.0.0.15") / TCP(sport=49152, dport=80, flags="PA", seq=1000) / scapy.Raw(load=http_payload)
    pkt5.time = base_time + 1.0
    packets.append(pkt5)

    # 5. FTP Cleartext Login
    pkt6 = Ether() / IP(src="192.168.1.60", dst="10.0.0.20") / TCP(sport=50100, dport=21, flags="PA", seq=2000) / scapy.Raw(load=b"USER backup_service\r\n")
    pkt6.time = base_time + 2.0
    packets.append(pkt6)

    pkt7 = Ether() / IP(src="192.168.1.60", dst="10.0.0.20") / TCP(sport=50100, dport=21, flags="PA", seq=2025) / scapy.Raw(load=b"PASS Spring2026!Secure\r\n")
    pkt7.time = base_time + 2.2
    packets.append(pkt7)

    # 6. TLS ClientHello with SNI and Ciphers
    # Construct a valid TLS 1.2 ClientHello byte sequence
    sni_bytes = b"c2.darknet-operation.com"
    sni_ext = b"\x00\x00" + (len(sni_bytes) + 5).to_bytes(2, "big") + (len(sni_bytes) + 3).to_bytes(2, "big") + b"\x00" + len(sni_bytes).to_bytes(2, "big") + sni_bytes
    curves_ext = b"\x00\x0a\x00\x04\x00\x02\x00\x1d"  # x25519
    points_ext = b"\x00\x0b\x00\x02\x01\x00"
    all_exts = sni_ext + curves_ext + points_ext

    ciphers = b"\xc0\x2f\xc0\x30\xcca\xcca\x00\x9f"
    client_random = b"\x01" * 32
    session_id = b"\x00"
    handshake_body = (
        b"\x03\x03" + client_random + session_id +
        len(ciphers).to_bytes(2, "big") + ciphers +
        b"\x01\x00" + len(all_exts).to_bytes(2, "big") + all_exts
    )
    handshake_header = b"\x01" + len(handshake_body).to_bytes(3, "big") + handshake_body
    tls_record = b"\x16\x03\x01" + len(handshake_header).to_bytes(2, "big") + handshake_header

    pkt8 = Ether() / IP(src="192.168.1.75", dst="198.51.100.44") / TCP(sport=51234, dport=443, flags="PA", seq=3000) / scapy.Raw(load=tls_record)
    pkt8.time = base_time + 3.0
    packets.append(pkt8)

    # 7. TCP SYN Port Scan (Source 192.168.1.99 scanning ports 20 to 45)
    for p in range(20, 42):
        syn_pkt = Ether() / IP(src="192.168.1.99", dst="10.0.0.50") / TCP(sport=60000 + p, dport=p, flags="S", seq=5000)
        syn_pkt.time = base_time + 4.0 + (p * 0.05)
        packets.append(syn_pkt)

    # 8. C2 Beaconing (Regular 1.0s interval)
    for i in range(10):
        b_pkt = Ether() / IP(src="192.168.1.120", dst="203.0.113.88") / TCP(sport=55555, dport=8443, flags="PA", seq=7000 + i*100) / scapy.Raw(load=b"BEACON_HEARTBEAT")
        b_pkt.time = base_time + 10.0 + (i * 1.002)  # Low jitter
        packets.append(b_pkt)

    scapy.wrpcap(output_path, packets)
    return output_path

if __name__ == "__main__":
    out = "test_threat_sample.pcap"
    create_sample_pcap(out)
    print(f"Sample PCAP created: {out}")
