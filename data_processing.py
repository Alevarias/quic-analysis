import os
import pyshark
import pandas as pd
from datetime import datetime

def main():
    pcap_dir = "captured_packets"
    records = []

    for fname in os.listdir(pcap_dir):
        if not fname.lower().endswith(".pcap"):
            continue

        path = os.path.join(pcap_dir, fname)
        cap = pyshark.FileCapture(path, keep_packets=False)

        try:
            first = next(iter(cap))
        except StopIteration:
            cap.close()
            continue
        t0: datetime = first.sniff_time

        cap.close()
        cap = pyshark.FileCapture(path, keep_packets=False)

        for pkt in cap:
            if not hasattr(pkt, 'quic'):
                continue


            rel_ts = pkt.sniff_time - t0
            rel_ts = rel_ts.total_seconds()

            size = int(pkt.frame_info.len)

            records.append({
                "pcap_file": fname, 
                "timestamp": rel_ts,
                "size": size, 
                "direction": None,  # Still need to add directionality functionality
                "label": fname.split("_")[0]
            })
        cap.close()

    # Convert to DataFrame and save as .csv
    df = pd.DataFrame(records, columns=["pcap_file", "timestamp", "size", "direction", "label"])
    df.to_csv("pcap_data.csv", index=False)

if __name__ == "__main__":
    main()