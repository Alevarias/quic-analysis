import time
import multiprocessing as mp
import subprocess
import os
import pyshark
import pandas as pd
import json
from datetime import datetime
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset
import sys
# import signal
import torch.nn.functional as F
import numpy as np

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
class_names = ["amazon", "chatgpt", "facebook", "google", "instagram", "linkedin", "twitter", "youtube"] 
# Defining the QUIC2DCNN model
class QUIC2DCNN(nn.Module):
    def __init__(self, num_classes: int, num_features: int = 3):
        super(QUIC2DCNN, self).__init__()
        # Convolutional feature extractor
        self.features = nn.Sequential(
            # conv1: cover all features (height=num_features) and small time window
            nn.Conv2d(in_channels=1, out_channels=16, kernel_size=(num_features, 5), padding=(0, 2)),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=(1, 2)),

            # conv2: temporal pattern
            nn.Conv2d(16, 32, kernel_size=(1, 5), padding=(0, 2)),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=(1, 2)),

            # conv3: deeper temporal
            nn.Conv2d(32, 64, kernel_size=(1, 5), padding=(0, 2)),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=(1, 2)),
        )
        # Global pooling to flatten spatial dims
        self.global_pool = nn.AdaptiveAvgPool2d((1, 1))

        # Classifier head
        self.classifier = nn.Sequential(
            nn.Flatten(),                # shape: (batch, 64)
            nn.Linear(64, 128),
            nn.ReLU(inplace=True),
            nn.Dropout(0.5),
            nn.Linear(128, num_classes)  # dynamic output size
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.features(x)
        x = self.global_pool(x)
        x = self.classifier(x)
        return x

def test_5_seconds():
    print("Starting packet capture...")
    # Test the 5 seconds capture time
    live_cap = pyshark.LiveCapture(interface='Wi-Fi', capture_filter= "udp port 443", display_filter='quic', decode_as={'udp.port==443': 'quic'})
    live_cap.keep_packets=True
    live_cap.sniff(timeout=5)  # Capture for 5 seconds
    live_cap.close()

    proc = getattr(live_cap, 'tshark_process', None) or getattr(live_cap, '_proc', None)
    if proc and proc.poll() is None:
        proc.terminate()       # send SIGTERM
        proc.wait()            # wait for it to die


    thread = getattr(live_cap, '_thread', None)
    if thread:
        thread.join()

    packets = list(live_cap._packets)
    live_cap.close()
    print(len(live_cap))

    timestamps = []
    sizes = []
    directions = []
    t0 = None
    
    print("Processing packets...")
    i = 0
    for pkt in packets:
        i+= 1
        # print("checking quic")
        if hasattr(pkt, 'quic'):
            if t0 is None:
                t0 = pkt.sniff_time
            rel_ts = (pkt.sniff_time - t0).total_seconds()
            timestamps.append(rel_ts)
            sizes.append(int(pkt.frame_info.len))

            # print(f"Timestamp: {rel_ts}, Size: {sizes}")
            # print("Added timestamp and size")

            if hasattr(pkt, 'transport_layer') and pkt.transport_layer == 'UDP':
                udp_layer = pkt[pkt.transport_layer]
                sport = int(udp_layer.srcport)
                dport = int(udp_layer.dstport)
            else: 
                directions.append(0)
                # print(f"Transport Layer Protocol: {pkt.transport_layer}")

            # print("Added direction")

            if dport == 443:
                directions.append(1)
            elif sport == 443:
                directions.append(-1)
            else:
                directions.append(0)

            # print(f"Packet {i}: Timestamp: {rel_ts}, Size: {sizes[-1]}, Direction: {directions[-1]}")


    print("Processing complete.")

    max_length = 1000
    NUM_CLASSES = 9
    NUM_FEATURES = 3
    MODEL_PATH = 'best_model.pth'

    timestamps = pad_truncate(timestamps, max_length)
    sizes = pad_truncate(sizes, max_length)
    directions = pad_truncate(directions, max_length)
    
    live_cap.close()
    
    print("Predicting class...")
    model = QUIC2DCNN(num_classes=NUM_CLASSES, num_features=NUM_FEATURES).to(device)
    model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
    model.eval()

    X = np.stack([
        sizes, 
        timestamps,
        directions
    ], axis=0)[None, ...]

    X = torch.tensor(X, dtype=torch.float32).unsqueeze(1).to(device)

    with torch.no_grad():
        logits = model(X)
    
        prediction = logits.softmax(1).argmax(1).item()
        prediction = class_names[prediction]
        print(f"Predicted class: {prediction}")



def pad_truncate(lst, length, pad_value=0):
    if len(lst) >= length:
        return lst[:length]
    else:
        return lst + [pad_value] * (length - len(lst))

    
# def scheduler():
#     procs = []

#     try:
#         while True:
#             print("Starting new process...")
#             p = mp.Process(target=test_5_seconds)
#             p.daemon = True # Ends the child processes when the parent process ends
#             p.start()
#             procs.append(p)

#             procs = [p for p in procs if p.is_alive()]

#             time.sleep(5)

#     except KeyboardInterrupt:
#         print("Stopping all processes...")
#         for p in procs:
#             p.terminate()
#             p.join()
#         print("All processes stopped.")
#         sys.exit(0)
    

def main():
    test_5_seconds()
    # scheduler()




if __name__ == "__main__":
    main()