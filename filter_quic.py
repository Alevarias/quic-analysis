#!/usr/bin/env python3
import os
import glob
import subprocess

# Directory containing your raw .pcap files
INPUT_DIR = "captured_packets"
# Directory where QUIC-only .pcap files will be saved
OUTPUT_DIR = "filtered_quic"

# Create the output directory if it doesn't exist
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Glob all .pcap files in the input directory
pattern = os.path.join(INPUT_DIR, "*.pcap")
for raw_path in glob.glob(pattern):
    # Preserve the original filename
    fname = os.path.basename(raw_path)
    out_path = os.path.join(OUTPUT_DIR, fname)

    print(f"Filtering {fname} → {out_path}")
    subprocess.run(
        [
            "tshark",
            "-r", raw_path,
            "-Y", "quic",
            "-w", out_path
        ],
        check=True
    )
    print(f"Saved QUIC-only pcap: {out_path}\n")

print("All files processed.")
