import os
import pyshark
import pandas as pd
import json
from datetime import datetime

MAX_LENGTH = 5000 # The 90th percentile using the packet_counter.py script

def pad_truncate(lst, length, pad_value=0):
    if len(lst) >= length:
        return lst[:length]
    else:
        return lst + [pad_value] * (length - len(lst))

def main():
    pcap_dir = "captured_packets"
    records = []

    for fname in os.listdir(pcap_dir):
        if not fname.lower().endswith(".pcap"):
            continue

        path = os.path.join(pcap_dir, fname)
        cap = pyshark.FileCapture(path, keep_packets=False)

        # Using first packet for initial timestamp
        try:
            first = next(iter(cap))
        except StopIteration:
            cap.close()
            continue
        t0: datetime = first.sniff_time
        cap.close()

        # Reopen the capture to process all packets
        cap = pyshark.FileCapture(path, keep_packets=False)

        # Initializing lists for timestamps and sizes
        timestamps = []
        sizes = [] 
        directions = []

        # Extracting QUIC packets and their details from .pcap files
        for pkt in cap:

            # Making extra sure that we're only processing QUIC packets
            if not hasattr(pkt, 'quic'):
                continue

            # Recording the relative timestamp
            rel_ts = (pkt.sniff_time - t0).total_seconds()
            timestamps.append(rel_ts)

            # Recording the packet size
            sizes.append(int(pkt.frame_info.len))

            # Recording the directionality of the packet
            try:
                sport = int(pkt.quic.srcport)
                dport = int(pkt.quic.dstport)
            except Exception:
                directions.append(0)
                continue

            # Labels directionality of the packet
            # Client to Server traffic should always have dport 443
            if dport == 443:
                directions.append(1)
            elif sport == 443:
                directions.append(-1)
            else:
                directions.append(0)
        cap.close()

        # Padding or truncating the lists to ensure they are of equal length
        max_length = 1000
        timestamps = pad_truncate(timestamps, max_length)
        sizes = pad_truncate(sizes, max_length)
        directions = pad_truncate(directions, max_length)

        # Adding to the records list
        records.append({
                "pcap_file": fname, 
                "timestamp": json.dumps(timestamps),
                "size": json.dumps(sizes), 
                "directionality": json.dumps(directions),  # Still need to add directionality functionality
                "label": fname.split("_")[0]
            })

    # Convert to DataFrame and save as .csv
    df = pd.DataFrame(records, columns=["pcap_file", "timestamp", "size", "directionality", "label"])
    df.to_csv("pcap_data.csv", index=False)

if __name__ == "__main__":
    main()