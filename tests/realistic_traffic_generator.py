"""Realistic Live Network Traffic Generator & Capture Engine.

Spins up local test services, performs genuine OS socket network transactions
(HTTP, TLS, Basic Auth, simulated DNS queries, port probes, and periodic beaconing),
and captures the live packets to a real PCAP file.
"""

import http.server
import socket
import threading
import time
import urllib.request
import scapy.all as scapy

# Mock HTTP Server handling realistic login and API requests
class RealisticHTTPHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress console logging noise

    def do_GET(self):
        auth_header = self.headers.get("Authorization")
        if self.path == "/api/login":
            if auth_header and "Basic" in auth_header:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "authenticated", "user": "finance_admin"}')
            else:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="Finance Portal"')
                self.end_headers()
                self.wfile.write(b'{"error": "Authentication required"}')
        elif self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "received", "bytes": ' + str(len(post_data)).encode() + b'}')


def run_realistic_scenario(output_pcap: str = "realistic_scenario.pcap"):
    print("=" * 60)
    print("STARTING REALISTIC NETWORK TRAFFIC GENERATION")
    print("=" * 60)

    # 1. Start local mock HTTP server on port 8999
    server_address = ("127.0.0.1", 8999)
    httpd = http.server.HTTPServer(server_address, RealisticHTTPHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    print("[+] Local web services started on 127.0.0.1:8999")

    # 2. Start background sniffer
    captured_packets = []
    def sniff_task():
        nonlocal captured_packets
        try:
            # Sniff loopback & active interface packets
            captured_packets = scapy.sniff(timeout=8)
        except Exception as e:
            print(f"[-] Sniff warning: {e}")

    sniffer_thread = threading.Thread(target=sniff_task)
    sniffer_thread.start()
    print("[+] Live packet sniffer listening on network interfaces...")
    time.sleep(1)

    # 3. Action A: Real Public Outbound Web & DNS Traffic (Real TLS & DNS)
    print("\n[*] Scenario A: Generating genuine outbound web & TLS traffic...")
    public_sites = ["https://www.wikipedia.org", "https://httpbin.org/get", "https://www.cloudflare.com"]
    for site in public_sites:
        try:
            req = urllib.request.Request(site, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                print(f"    -> Connected to {site} (HTTP {resp.status})")
        except Exception as e:
            print(f"    -> Note connecting to {site}: {e}")

    # 4. Action B: Real HTTP Basic Auth Transmission to Local Portal
    print("\n[*] Scenario B: Generating real HTTP authentication transaction...")
    try:
        auth_req = urllib.request.Request(
            "http://127.0.0.1:8999/api/login",
            headers={
                "Authorization": "Basic ZmluYW5jZV9hZG1pbjpIVW43M3JTY29ycGlvbjEyMyE=",  # finance_admin:HUn73rScorpion123!
                "User-Agent": "InternalPortalClient/1.2",
            },
        )
        with urllib.request.urlopen(auth_req, timeout=2) as resp:
            data = resp.read().decode()
            print(f"    -> Successfully executed HTTP Basic Auth login: {data}")
    except Exception as e:
        print(f"    -> Auth request failed: {e}")

    # 5. Action C: Real HTTP POST with sensitive parameters
    print("\n[*] Scenario C: Generating real HTTP POST with API keys...")
    try:
        post_req = urllib.request.Request(
            "http://127.0.0.1:8999/api/submit",
            data=b"action=update_config&api_key=sk_live_9948271038591023&secret_token=abc123xyz",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(post_req, timeout=2) as resp:
            print(f"    -> Successfully sent POST payload: {resp.read().decode()}")
    except Exception as e:
        print(f"    -> Post request failed: {e}")

    # 6. Action D: Periodic C2 Heartbeat Simulation (Real OS sockets)
    print("\n[*] Scenario D: Simulating periodic heartbeat beaconing over real sockets...")
    for i in range(4):
        try:
            with socket.create_connection(("127.0.0.1", 8999), timeout=1) as s:
                s.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                s.recv(1024)
            print(f"    -> Beacon #{i+1} sent (interval 0.75s)")
            time.sleep(0.75)
        except Exception as e:
            print(f"    -> Beacon error: {e}")

    # 7. Action E: Fast Port Sweep Probe
    print("\n[*] Scenario E: Performing local TCP port sweep across ports 9000-9010...")
    for p in range(9000, 9012):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        try:
            s.connect_ex(("127.0.0.1", p))
        except Exception:
            pass
        finally:
            s.close()

    print("\n[+] Waiting for sniffer to finalize...")
    sniffer_thread.join()
    httpd.shutdown()

    if captured_packets:
        scapy.wrpcap(output_pcap, captured_packets)
        print(f"\n[OK] CAPTURE COMPLETE: Saved {len(captured_packets)} real network packets to '{output_pcap}'")
    else:
        print("[-] Note: No packets captured.")

    return output_pcap


if __name__ == "__main__":
    run_realistic_scenario("realistic_scenario.pcap")
