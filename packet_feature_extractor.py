from scapy.all import *
import pandas as pd
from collections import defaultdict

def get_flow_key(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        
        src_port = pkt.sport if hasattr(pkt, "sport") else 0
        dst_port = pkt.dport if hasattr(pkt, "dport") else 0
        
        return (src_ip, dst_ip, src_port, dst_port, proto)
    return None

flows = defaultdict(lambda: {
    "start": None,
    "end": None,
    "pkt_count": 0,
    "byte_count": 0,
    "flags": {"SYN":0, "FIN":0, "RST":0, "PSH":0, "ACK":0}
})

pcap = rdpcap("traffic.pcap")

for pkt in pcap:
    key = get_flow_key(pkt)
    if not key:
        continue
    
    flow = flows[key]
    ts = pkt.time
    
    # Set start time
    if flow["start"] is None:
        flow["start"] = ts
    flow["end"] = ts
    
    # Count packets & bytes
    flow["pkt_count"] += 1
    flow["byte_count"] += len(pkt)
    
    # Extract TCP flags if present
    if TCP in pkt:
        tcp_flags = pkt[TCP].flags
        if tcp_flags & 0x02: flow["flags"]["SYN"] += 1
        if tcp_flags & 0x01: flow["flags"]["FIN"] += 1
        if tcp_flags & 0x04: flow["flags"]["RST"] += 1
        if tcp_flags & 0x08: flow["flags"]["PSH"] += 1
        if tcp_flags & 0x10: flow["flags"]["ACK"] += 1

rows = []
for key, feat in flows.items():
    src_ip, dst_ip, src_port, dst_port, proto = key
    duration = feat["end"] - feat["start"] if feat["end"] and feat["start"] else 0
    
    row = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "duration": duration,
        "pkt_count": feat["pkt_count"],
        "byte_count": feat["byte_count"],
        "syn_count": feat["flags"]["SYN"],
        "fin_count": feat["flags"]["FIN"],
        "rst_count": feat["flags"]["RST"],
        "psh_count": feat["flags"]["PSH"],
        "ack_count": feat["flags"]["ACK"]
    }
    rows.append(row)

df = pd.DataFrame(rows)
df.to_csv("flow_features.csv", index=False)
print("Flow features exported to flow_features.csv")
