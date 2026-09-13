from collections import defaultdict
from typing import Any, Dict, List, Optional
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

def reassemble_stream(
    pcap_path: str,
    stream_index: int = 0,
    protocol: str = "tcp",
    max_payload_bytes: int = 65536,
) -> Dict[str, Any]:
    """Reassemble and extract raw conversation stream from a PCAP.
    
    Args:
        pcap_path: Path to capture file.
        stream_index: Zero-based stream index (or Wireshark stream number).
        protocol: 'tcp' or 'udp'.
        max_payload_bytes: Truncate stream payload to this limit to protect context window.
    """
    packets = scapy.rdpcap(pcap_path)
    streams = defaultdict(list)
    
    layer_type = TCP if protocol.lower() == "tcp" else UDP
    
    for idx, pkt in enumerate(packets):
        if not pkt.haslayer(layer_type) or not pkt.haslayer(scapy.Raw):
            continue
            
        src_ip = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "0.0.0.0")
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else "0.0.0.0")
        sport = pkt[layer_type].sport
        dport = pkt[layer_type].dport
        
        ep1 = f"{src_ip}:{sport}"
        ep2 = f"{dst_ip}:{dport}"
        stream_key = tuple(sorted([ep1, ep2]))
        
        streams[stream_key].append({
            "packet_num": idx + 1,
            "timestamp": float(pkt.time),
            "direction": f"{ep1} -> {ep2}",
            "src": ep1,
            "dst": ep2,
            "seq": pkt[TCP].seq if protocol.lower() == "tcp" and pkt.haslayer(TCP) else 0,
            "payload": bytes(pkt[scapy.Raw].load),
        })

    stream_keys = list(streams.keys())
    if stream_index < 0 or stream_index >= len(stream_keys):
        return {
            "error": f"Stream index {stream_index} out of range. Total streams: {len(stream_keys)}",
            "available_streams_count": len(stream_keys),
        }

    target_key = stream_keys[stream_index]
    raw_chunks = streams[target_key]

    # Assemble conversation transcript
    transcript = []
    total_bytes = 0
    truncated = False

    for chunk in raw_chunks:
        payload_data = chunk["payload"]
        total_bytes += len(payload_data)
        
        text = payload_data.decode("utf-8", "replace")
        transcript.append(f"[{chunk['direction']} (Pkt #{chunk['packet_num']})]:\n{text}\n")
        
        if total_bytes > max_payload_bytes:
            transcript.append(f"\n[... STREAM TRUNCATED AT {max_payload_bytes} BYTES ...]")
            truncated = True
            break

    return {
        "stream_index": stream_index,
        "endpoints": f"{target_key[0]} <-> {target_key[1]}",
        "protocol": protocol.upper(),
        "total_packets_in_stream": len(raw_chunks),
        "total_stream_bytes": total_bytes,
        "truncated": truncated,
        "stream_content": "\n".join(transcript),
    }
