# Wireshark MCP - AI-Powered Network Forensics

> **Automated packet triage, TLS fingerprinting, and threat hunting for LLMs.**

---

## Description

Wireshark MCP is a production-grade Model Context Protocol (MCP) server engineered specifically for Security Engineers, Incident Responders, Network Architects, and SOC Analysts. It connects Large Language Models (such as Google Gemini, Anthropic Claude, and OpenAI GPT-4) directly to network packet analysis engines.

Instead of manually navigating Wireshark desktop GUIs, crafting complex display filters, or converting PCAP bytes by hand, security teams can pair program with an AI assistant to triage packet captures (.pcap, .pcapng, .cap) in natural language. The server natively parses protocol hierarchies, extracts TLS ClientHello metadata and JA3 fingerprints, calculates Shannon entropy for DNS tunneling/DGA detection, hunts for cleartext credential exposures, and reassembles full-duplex TCP/UDP conversations into structured JSON evidence.

---

## Key Features

- **Dual-Engine Processing:**
  - **TShark Engine:** Executes native Wireshark display filter queries (-Y) and statistics when tshark CLI is installed.
  - **Pure-Python Engine (scapy):** 100% memory-safe fallback that runs natively anywhere without requiring Wireshark pre-installed.
- **Automated Threat Hunting & Credential Hunter:**
  - Decodes HTTP Basic Authentication headers from Base64 into cleartext credentials.
  - Extracts plaintext FTP USER / PASS commands, Telnet terminal interactions, and API keys passed in HTTP POST bodies.
  - Detects TCP SYN port scanning sweeps and reconnaissance activities.
  - Identifies periodic, low-jitter Command-and-Control (C2) heartbeat beaconing intervals.
- **DNS Exfiltration & DGA Forensics:**
  - Calculates Shannon entropy across domains and subdomains to flag encrypted/base64 tunneling exfiltration.
  - Flags excessive subdomain lengths, high NXDOMAIN failure ratios, and oversized TXT / NULL records.
- **Cryptographic Forensics & JA3/JA4 Fingerprinting:**
  - Dissects TLS ClientHellos without decrypting payloads.
  - Maps Server Name Indication (SNI) hostnames and computes MD5 JA3 client hashes for malware and client attribution.
- **Conversational Stream Reassembly:**
  - Reassembles bidirectional TCP and UDP flows into complete, ordered, human-readable text transcripts.
- **Dual Ingestion Modes:**
  - Supports absolute local file paths on disk as well as direct Base64-encoded binary payload uploads (upload_pcap / analyze_uploaded_pcap).
- **Enterprise Hardened Security:**
  - Strict path traversal prevention, 50MB upload size caps, subprocess execution timeouts, and prompt injection mitigation.

---

## System Architecture

The following diagram illustrates the complete end-to-end architecture of the Wireshark MCP system, showing how AI assistants, protocol engines, forensic analyzers, and storage layers interact:

```mermaid
graph TD
    subgraph ClientLayer["1. AI Client & User Interface Layer"]
        Gemini["Google Gemini (Antigravity IDE)"]
        Claude["Anthropic Claude (Desktop / API)"]
        Inspector["MCP Inspector (Web UI)"]
        CustomAgent["Custom SOC Automation / SOAR"]
    end

    subgraph ProtocolLayer["2. Model Context Protocol (MCP) Interface"]
        StdioTransport["Stdio Transport (JSON-RPC 2.0)"]
        ServerCore["FastMCP Server Router (wireshark_mcp.server)"]
    end

    subgraph EngineRouter["3. Engine Routing & Execution Layer"]
        Detector["Binary Detector (find_tshark)"]
        TSharkEngine["TShark CLI Engine (Native Wireshark Filters)"]
        ScapyEngine["Scapy Python Engine (Memory-Safe Fallback)"]
    end

    subgraph Analyzers["4. Forensic & Security Analyzers"]
        DNSAnalyzer["DNS Forensics & Shannon Entropy Analyzer"]
        TLSAnalyzer["TLS SNI & JA3 Fingerprint Extractor"]
        ThreatHunter["Threat & Credential Hunter (HTTP/FTP/SYN/C2)"]
        StreamReassembler["TCP/UDP Conversation Stream Reassembler"]
        UploadManager["PCAP Ingestion & Sanitization Manager"]
    end

    subgraph DataLayer["5. Data & Storage Layer"]
        LocalPCAP["Local PCAP / PCAPNG Files"]
        UploadStorage["Sandboxed Upload Storage (TEMP/wireshark_mcp_uploads)"]
    end

    ClientLayer -->|JSON-RPC Requests| StdioTransport
    StdioTransport --> ServerCore
    ServerCore --> Detector
    Detector -->|If tshark in PATH/env| TSharkEngine
    Detector -->|Native / Fallback| ScapyEngine
    
    ServerCore --> DNSAnalyzer
    ServerCore --> TLSAnalyzer
    ServerCore --> ThreatHunter
    ServerCore --> StreamReassembler
    ServerCore --> UploadManager

    UploadManager --> UploadStorage
    TSharkEngine --> LocalPCAP
    TSharkEngine --> UploadStorage
    ScapyEngine --> LocalPCAP
    ScapyEngine --> UploadStorage
```

<div align="center">
  <b>Figure 1: Wireshark MCP End-to-End System Architecture</b>
</div>

---

### Flow-by-Flow Explanation of the Architecture

1. **Client Request Initiation (Layer 1):** The user or security engineer submits a natural language query (e.g., "Audit this PCAP for credential leaks and DNS tunneling") through their AI assistant (Google Gemini in Antigravity, Claude Desktop, or custom Python SOAR script).
2. **MCP JSON-RPC Handshake (Layer 2):** The AI client sends a standard JSON-RPC tools/call message over standard input/output (stdio) to the FastMCP server core.
3. **Engine Routing (Layer 3):** The Binary Detector determines the execution engine. If native Wireshark filters (-Y) are requested and tshark is discovered, it routes to TSharkEngine; otherwise, it utilizes the native ScapyEngine.
4. **Deep Forensic Inspection (Layer 4):**
   - The **DNS Analyzer** calculates mathematical Shannon entropy ($H = -\sum p_i \log_2 p_i$) on domain strings and checks NXDOMAIN ratios.
   - The **TLS Analyzer** extracts unencrypted ClientHello fields (SNI, ciphers, curves) and generates MD5 JA3 hashes.
   - The **Threat Hunter** runs regex scanners across raw payload layers to extract HTTP Basic Auth, FTP credentials, SYN flood anomalies, and beaconing intervals.
   - The **Stream Reassembler** sequences packet TCP payloads into readable text transcripts.
5. **Data & Storage Access (Layer 5):** The analyzers read raw bytes from local .pcap files or sandboxed temporary files ingested via upload_pcap.
6. **Structured Response Return:** The server packages the findings into clean, structured JSON and sends it back via JSON-RPC to the LLM for synthesis into a final human report.

---

## Tech Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Language** | Python 3.10+ | Core programming language |
| **MCP Protocol** | mcp>=1.0.0 (Official MCP Python SDK) | Standardized Model Context Protocol client-server transport |
| **Packet Parsing** | scapy>=2.5.0 | Pure-Python raw packet decoding, Layer 2-7 dissection, PCAP reading/writing |
| **Native Engine** | Wireshark tshark CLI | Full Wireshark display filter execution and statistics |
| **Validation** | pydantic>=2.0.0 | Strict data validation and schema definitions |
| **Testing** | pytest>=8.0.0 | Comprehensive unit and integration test suite |

---

## Setup & Installation

### 1. Navigate to the Project Directory
```powershell
cd C:\Users\ritvi\.gemini\antigravity\scratch\wireshark-mcp
```

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Verify the Test Suite
Run the automated test suite against synthetic multi-vector threat captures:
```powershell
python -m pytest -v
```

### 4. Configure in Antigravity / Claude Desktop

#### For Antigravity:
Open `C:\Users\ritvi\.gemini\config\mcp_config.json` and add:

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "C:\\Python314\\python.exe",
      "args": [
        "-m",
        "wireshark_mcp.server"
      ],
      "env": {
        "PYTHONPATH": "C:\\Users\\ritvi\\.gemini\\antigravity\\scratch\\wireshark-mcp"
      }
    }
  }
}
```

#### For Claude Desktop:
Open `%APPDATA%\Claude\claude_desktop_config.json` and add:

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "python",
      "args": [
        "-m",
        "wireshark_mcp.server"
      ],
      "cwd": "C:\\Users\\ritvi\\.gemini\\antigravity\\scratch\\wireshark-mcp"
    }
  }
}
```

---

## Why Gemini in Antigravity is Uniquely Suited

When running Wireshark MCP inside the Antigravity IDE, Google Gemini models (specifically **Gemini 1.5 Pro** and **Gemini 2.0 Flash / Pro**) provide distinct architectural advantages for network forensics and packet inspection:

1. **Massive Context Window (1M - 2M Tokens):**
   Packet captures and reconstructed conversational streams generate extensive text volumes. While standard models with 32K or 128K token limits quickly saturate or force aggressive truncation, **Gemini 1.5 Pro** natively ingests full multi-megabyte stream transcripts, thousands of DNS queries, and long conversation tables in a single prompt without losing needle-in-a-haystack threat indicators.

2. **Advanced Multi-Modal & Structured JSON Reasoning:**
   Network forensics outputs contain nested, heterogeneous JSON data structures (JA3 hashes, cipher arrays, Shannon entropy floating-point scores, IP-to-port maps). **Gemini 2.0 Flash** excels at high-speed structured data correlation—matching a high-entropy subdomain from `extract_dns_forensics` to an encrypted external TLS handshake extracted by `extract_tls_fingerprints` from the same client IP.

3. **Autonomous Multi-Step Tool Calling:**
   Gemini's function-calling engine natively orchestrates multi-tool investigation pipelines in a single user turn (e.g., executing `pcap_overview` -> detecting an anomaly -> calling `scan_suspicious_indicators` -> calling `follow_stream` on the suspicious flow -> synthesizing a root-cause incident report).

---

## How to Use the App (Step-by-Step Walkthrough)

### Step 1: Open Your AI Assistant
Launch Antigravity IDE (with Gemini) or Claude Desktop. Ensure the wireshark MCP server is active in your configuration.

---

### Step 2: Check Engine Status
Ask your assistant:
> "Check the status of the Wireshark analysis engines."

**Expected Output:** The AI calls `get_engine_status()` and confirms whether tshark is discovered and lists all 10 active analysis capabilities.

---

### Step 3: Run Rapid PCAP Triage on an Existing File
Provide any .pcap or .pcapng path on your disk:
> "Run an end-to-end incident triage on C:\Users\ritvi\.gemini\antigravity\scratch\wireshark-mcp\sample_attack.pcap."

**The AI automatically:**
1. Calls `pcap_overview` -> Reports duration, packet count, and protocol distribution.
2. Calls `scan_suspicious_indicators` -> Uncovers plaintext credentials (HTTP Basic Auth, FTP credentials) and port scans.
3. Calls `extract_dns_forensics` -> Flags high-entropy DNS tunneling queries and DGA domains.
4. Calls `extract_tls_fingerprints` -> Extracts JA3 hashes and SNIs.

---

### Step 4: Reassemble and Read a Specific Conversation Stream
When you spot a suspicious communication:
> "Follow and reconstruct TCP stream #0 in sample_attack.pcap."

**The AI outputs:** The exact HTTP GET/POST headers, payloads, or raw conversation transcript.

---

### Step 5: Capture Live Traffic Directly from Your Machine
If you do not have a capture file on hand:
> "Capture 50 live packets from my network adapter and analyze the traffic."

**The AI will:**
1. Execute a live network sniff via Scapy on your network card.
2. Save the trace to `live_sniff_50.pcap`.
3. Dissect local mDNS devices, active endpoints, and security indicators.

---

### Step 6: Test with the Interactive MCP Inspector UI
To visually test all tools in a web dashboard:
```powershell
npx @modelcontextprotocol/inspector python -m wireshark_mcp.server
```
1. Open your browser to `http://localhost:5173`.
2. Click on any tool (e.g. `pcap_overview`, `extract_dns_forensics`).
3. Enter arguments and click Run Tool to inspect live JSON responses.

---

## Technical Documentation

For the comprehensive engineering architecture, mathematical formulas, agent workflows, security threat model, and detailed feature specifications:

[Read the Full Technical Documentation](TECHNICAL_DOCUMENTATION.md)

---

## License & Author

- **Author:** Ritvik Indupuri
- **Version:** 0.1.0
- **License:** MIT