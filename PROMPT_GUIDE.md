# Wireshark MCP Server - Prompt Guide & Capabilities Reference

This document serves as the complete query reference guide for the **Wireshark & PCAP Threat Triage MCP Server**.

---

## Category 1: When You DO NOT Have a PCAP Yet (Creation & Capture)

If you don't have a PCAP file yet, you can ask the agent to capture, create, or fetch one:

| Scenario | Example Prompts |
| :--- | :--- |
| **Sniff Live Network Traffic** | • "Capture 50 live packets from my local network interface and analyze the traffic."<br>• "Start a 10-second packet sniff on my machine and tell me what external servers my computer is talking to." |
| **Generate Test Attack Traffic** | • "Generate a realistic test PCAP containing HTTP basic auth, a port scan, and DNS queries, then save it to disk."<br>• "Create a simulated malware C2 beaconing capture so I can test my detection rules." |
| **Fetch Public/Malware Datasets** | • "Download a sample malware or HTTP capture from the official Wireshark repository and inspect it."<br>• "Fetch a real-world PCAP from a public repo and run a forensic check." |
| **Inspect Server Status** | • "Check the status of the Wireshark analysis engines and tell me what tools are active."<br>• "Is tshark installed on my machine, or are we using the Scapy fallback engine?" |

---

## Category 2: Security Incident Response & Threat Hunting

When investigating a potential breach, intrusion, or suspicious activity:

| Detection Goal | Example Prompts |
| :--- | :--- |
| **Full Triage Report** | • "Perform an end-to-end incident triage on <path_to_file.pcap> and give me an executive summary of threats found."<br>• "Run a full security audit on <path_to_file.pcap>." |
| **Credential Leak Hunting** | • "Scan <path_to_file.pcap> for any cleartext passwords, FTP logins, HTTP Basic Auth headers, or exposed API keys."<br>• "Are there any unencrypted credentials or session tokens passing through this network trace?" |
| **DNS Tunneling & DGA Detection** | • "Analyze DNS traffic in <path_to_file.pcap> for data exfiltration or high-entropy tunneling queries."<br>• "Check the capture for high rates of NXDOMAIN responses or domain generation algorithms (DGA)."<br>• "Show me all large DNS TXT or NULL records that might indicate tunneling." |
| **C2 Beaconing & Timing Analysis** | • "Check <path_to_file.pcap> for persistent, periodic beaconing or low-jitter C2 heartbeat flows."<br>• "Are any internal hosts sending regular heartbeats to external IP addresses?" |
| **Reconnaissance & Port Scanning** | • "Did any host perform a port scan or TCP SYN sweep in <path_to_file.pcap>?"<br>• "Identify any suspicious IP addresses that probed multiple ports." |

---

## Category 3: TLS, SSL & Cryptographic Forensics

When analyzing encrypted traffic without breaking encryption:

| Goal | Example Prompts |
| :--- | :--- |
| **JA3 Client Fingerprinting** | • "Extract all TLS JA3 client fingerprints from <path_to_file.pcap> and group them by client application."<br>• "Are there any unusual or rare JA3 hashes communicating with external servers?" |
| **SNI & Unencrypted Hostnames** | • "List all TLS Server Name Indication (SNI) hostnames requested in <path_to_file.pcap>."<br>• "Show me which internal IP addresses connected to which domain names over HTTPS." |
| **Cipher Suite & Protocol Auditing** | • "What TLS versions and cipher suites are being used in <path_to_file.pcap>?" |

---

## Category 4: Network Diagnostics & Protocol Investigation

When debugging connectivity, bandwidth hogs, or protocol errors:

| Goal | Example Prompts |
| :--- | :--- |
| **Capture Overview & Stats** | • "Give me a protocol breakdown and total packet count for <path_to_file.pcap>."<br>• "What is the start time, end time, and total duration of this capture?" |
| **Top Talkers & Bandwidth** | • "Who are the top IP talkers in <path_to_file.pcap> by byte volume?"<br>• "List the top TCP conversations and rank them by total packets transferred." |
| **Stream Reassembly** | • "Follow and reconstruct TCP stream #0 in <path_to_file.pcap> and show me the full conversation payload."<br>• "Reassemble the HTTP conversation between 10.0.0.5 and 207.46.134.94." |
| **Wireshark Display Filters** | • "Apply the Wireshark filter http.request.method == 'POST' to <path_to_file.pcap>."<br>• "Filter this PCAP for tcp.flags.syn == 1 && tcp.flags.ack == 0 and show me the first 20 matching packets." |

---

## Category 5: Direct Upload & Base64 Ingestion (Web / Remote)

When interacting via a web chat, API, or remote interface without direct local file path access:

| Goal | Example Prompts |
| :--- | :--- |
| **Upload and Triage in One Shot** | • "Here is the base64-encoded PCAP data: <base64_string>. Upload it and run a full threat analysis."<br>• "Analyze this uploaded capture: analyze_uploaded_pcap(base64_data='...')." |
| **Upload for Step-by-Step Querying** | • "Upload this base64 capture with filename incident.pcap: <base64_string>."<br>• (Follow-up prompt) "Now extract the DNS records and TLS fingerprints from the uploaded file." |

---

## Category 6: Wireshark Syntax & Filter Assistance

When you need help constructing Wireshark filter rules:

| Goal | Example Prompts |
| :--- | :--- |
| **Filter Generation** | • "How do I write a Wireshark display filter to find all DNS queries for .xyz domains?"<br>• "What is the display filter syntax to find TCP retransmissions or reset packets?"<br>• "Generate a filter for TLS 1.2 ClientHello packets that do not use SNI." |
