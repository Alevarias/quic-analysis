import os
import numpy as np
from scapy.utils import RawPcapReader

# Path for the folder containing filtered QUIC .pcap files
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PCAP_FOLDER = os.path.join(BASE_DIR, "filtered_quic")


def count_packets(pcap_path):
    reader = RawPcapReader(pcap_path)
    count = 0
    for _ in reader:
        count += 1
    reader.close()
    return count


def find_pcap_files(folder):
    pcap_files = []
    for root, dirs, files in os.walk(folder):
        for fname in files:
            if fname.lower().endswith(".pcap"):
                pcap_files.append(os.path.join(root, fname))
    return pcap_files


def main():
    folder = PCAP_FOLDER
    pcaps = find_pcap_files(folder)
    if not pcaps:
        print(f"No .pcap files found under '{folder}'.")
        return

    counts = []
    for pcap in pcaps:
        c = count_packets(pcap)
        print(f"{os.path.basename(pcap):<40} → {c:>6} packets")
        counts.append(c)

    # Compute the 90th percentile
    p90 = np.percentile(counts, 90)
    print(f"\n90th percentile packet count: {p90:.0f}")


if __name__ == "__main__":
    main()