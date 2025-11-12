# Packet Feature Extractor 

---

## Introduction
In SOC operations, packet-level visibility is critical — but not always actionable.  
Analysts and machine learning models both perform better when traffic is represented as **flows** (communication between src_ip:src_port → dst_ip:dst_port over a protocol).  

This project builds a **Python-based Packet Feature Extractor** that converts raw **PCAP** files into structured **flow-level CSV datasets**, making them suitable for behavior analysis, anomaly detection, and ML-driven intrusion detection systems.

---

## Objectives
- Parse PCAPs into **network flows**
- Extract meaningful **flow features**:
  - Flow identifiers (source/destination IP, ports, protocol)
  - Start & end time, duration
  - Total packets & bytes
  - TCP flag counts (SYN, FIN, RST, PSH, ACK)
- Save flows as **CSV** for further analysis

---

## Dependencies
- **Python:** 3.10+
- **Libraries:**
  - `scapy`
  - `pandas`

---

## ⚙️ How It Works

### 1️⃣ Parse the PCAP
Using `scapy.rdpcap()` to load raw packets from `traffic.pcap`.

### 2️⃣ Identify Flows
Each packet is grouped into a 5-tuple key:

(src_ip, dst_ip, src_port, dst_port, protocol)


### 3️⃣ Extract Features
For each flow:
- Track start and end times  
- Count packets and bytes  
- Count TCP flags (SYN, FIN, RST, PSH, ACK)

### 4️⃣ Export to CSV
All features are stored in a `pandas` DataFrame and exported to `flow_features.csv`.

---

## Output Example
| src_ip | dst_ip | src_port | dst_port | proto | duration | pkt_count | byte_count | syn_count | fin_count | rst_count | psh_count | ack_count |
|--------|--------|-----------|-----------|--------|-----------|------------|-------------|------------|------------|------------|------------|------------|
| 192.168.1.10 | 142.250.190.78 | 53421 | 443 | 6 | 1.25 | 15 | 1620 | 1 | 1 | 0 | 4 | 12 |

---

## SOC Relevance
- Converts raw packets into analyst-friendly flow statistics.
- Enables **traffic profiling** and **feature engineering** for AI/ML-based detection.
- Supports **incident triage**, **threat hunting**, and **behavioral baselining**.
- Ideal for building datasets for **Supervised IDS** models (benign vs malicious).

---

## Example Use Case
```bash
python packet_feature_extractor.py
````

**Output:** flow_features.csv
**Each row =** one network flow
**Each column =** a feature useful for further detection or ML analysis.

## Repository Purpose:
To demonstrate SOC-grade Python automation for transforming packet captures into intelligence-ready flow features.


