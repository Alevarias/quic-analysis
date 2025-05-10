import os
import json
import torch
import pyshark
import logging
from datetime import datetime, timedelta
from typing import List, Tuple, Dict, Any
import signal
import sys
import traceback
from collections import defaultdict

# Constants
MODEL_PATH = "C:\\Users\\aisha\\Downloads\\best_model.pth"
TRAINER_PATH = "C:\\Users\\aisha\\Downloads\\quic_cnn_trainer.py"
NUM_FEATURES = 3
SEQUENCE_LENGTH = 1000
CAPTURE_DURATION = timedelta(seconds=20)
ANALYSIS_WINDOW = timedelta(seconds=5)
NETWORK_INTERFACE = 'Wi-Fi'
RESULTS_FILE = "quic_classification_log.jsonl"  # JSON Lines format

# Application labels
CLASS_LABELS = [
    'amazon', 'chatgpt', 'facebook', 'google',
    'instagram', 'linkedin', 'twitter', 'yahoo', 'youtube'
]


class QUICClassifierLogger:
    """Handles all logging operations to a single file."""

    def __init__(self, filename=RESULTS_FILE):
        self.filename = filename
        self._setup_log_file()

    def _setup_log_file(self):
        """Initialize the log file with headers if new."""
        if not os.path.exists(self.filename):
            with open(self.filename, 'w') as f:
                f.write("# QUIC Classification Log - JSON Lines Format\n")

    def log_result(self, data):
        """Append a classification result to the log file."""
        with open(self.filename, 'a') as f:
            json.dump(data, f)
            f.write('\n')  # JSON Lines format


class LiveQUICClassifier:
    def __init__(self):
        """Initialize classifier with logging capability."""
        self.device = self._get_device()
        self.model = self._load_model()
        self.packets = []
        self.logger = QUICClassifierLogger()
        self._setup_signal_handlers()

    def _get_device(self):
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logging.info("Using device: {0}".format(device))
        return device

    def _load_model(self):
        """Dynamically load the model from specified paths."""
        try:
            # Dynamic import of trainer module
            import importlib.util
            spec = importlib.util.spec_from_file_location("quic_cnn_trainer", TRAINER_PATH)
            trainer_module = importlib.util.module_from_spec(spec)
            sys.modules["quic_cnn_trainer"] = trainer_module
            spec.loader.exec_module(trainer_module)

            model = trainer_module.QUIC2DCNN(
                num_classes=len(CLASS_LABELS),
                num_features=NUM_FEATURES
            )
            model.load_state_dict(torch.load(MODEL_PATH, map_location=self.device))
            model.to(self.device).eval()
            logging.info("Model loaded successfully from: {0}".format(MODEL_PATH))
            return model
        except Exception as e:
            logging.error("Model loading failed: {0}".format(str(e)))
            raise

    def _setup_signal_handlers(self):
        signal.signal(signal.SIGINT, self._handle_interrupt)
        signal.signal(signal.SIGTERM, self._handle_interrupt)

    def _handle_interrupt(self, signum, frame):
        """Ensure log is flushed before exit."""
        self.logger.log_result({
            "event": "shutdown",
            "timestamp": datetime.now().isoformat(),
            "packets_captured": len(self.packets)
        })
        sys.exit(0)

    def capture_packets(self):
        """Capture packets with enhanced metadata collection."""
        logging.info("Starting {0}s capture on interface {1}".format(
            CAPTURE_DURATION.total_seconds(),
            NETWORK_INTERFACE
        ))

        capture = pyshark.LiveCapture(
            interface=NETWORK_INTERFACE,
            display_filter='quic',
            use_json=True
        )

        start = datetime.now()
        for pkt in capture.sniff_continuously():
            if (datetime.now() - start) > CAPTURE_DURATION:
                break
            self._process_packet(pkt)

        logging.info("Capture complete. Collected {0} packets".format(len(self.packets)))
        print(self.packets)
    def _process_packet(self, packet):
        """Extract and store packet data with verification info."""
        if not hasattr(packet, 'quic'):
            return

        try:
            self.packets.append({
                "timestamp": float(packet.frame_info.time_relative),
                "size": int(packet.length),
                "source_ip": getattr(packet.ip, 'src', 'unknown'),
                "destination_ip": getattr(packet.ip, 'dst', 'unknown'),
                "source_port": getattr(packet.udp, 'srcport', 'unknown'),
                "destination_port": getattr(packet.udp, 'dstport', 'unknown')
            })
        except Exception as e:
            logging.warning("Packet processing error: {0}".format(str(e)))

    def _generate_verification_metrics(self):
        """Generate comprehensive verification metrics."""
        if not self.packets:
            return {}

        sizes = [p['size'] for p in self.packets]
        times = [p['timestamp'] for p in self.packets]

        # Port analysis
        port_counts = defaultdict(int)
        for p in self.packets:
            port_counts["{0}->{1}".format(p['source_port'], p['destination_port'])] += 1

        return {
            "packet_stats": {
                "count": len(self.packets),
                "size_distribution": {
                    "mean": sum(sizes) / len(sizes),
                    "min": min(sizes),
                    "max": max(sizes)
                },
                "time_metrics": {
                    "duration_seconds": times[-1] - times[0],
                    "packets_per_second": len(times) / (times[-1] - times[0])
                }
            },
            "network_metrics": {
                "top_ports": dict(sorted(
                    port_counts.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]),
                "unique_ips": len({
                    (p['source_ip'], p['destination_ip'])
                    for p in self.packets
                })
            }
        }

    def classify_and_log(self):
        """Complete classification pipeline with logging."""
        try:
            self.capture_packets()

            if not self.packets:
                raise RuntimeError("No packets captured")

            # Prepare input tensor
            window = self.packets[-1000:]  # Last 1000 packets
            sizes = [p['size'] for p in window]
            times = [p['timestamp'] - window[0]['timestamp'] for p in window]
            directions = [1] * len(window)

            tensor = torch.tensor(
                [(sizes[:SEQUENCE_LENGTH] + [0] * SEQUENCE_LENGTH)[:SEQUENCE_LENGTH],
                 (times[:SEQUENCE_LENGTH] + [0] * SEQUENCE_LENGTH)[:SEQUENCE_LENGTH],
                 (directions[:SEQUENCE_LENGTH] + [0] * SEQUENCE_LENGTH)[:SEQUENCE_LENGTH]],
                dtype=torch.float32
            ).unsqueeze(0).unsqueeze(0).to(self.device)

            # Run classification
            with torch.no_grad():
                logits = self.model(tensor)
                probs = torch.softmax(logits, dim=1)
                conf, idx = torch.max(probs, dim=1)
                prediction = CLASS_LABELS[idx]

                #Prepare complete log entry
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "prediction": prediction,
                    "confidence": float(conf.item()),
                    "model": {
                        "name": "QUIC2DCNN",
                        "path": MODEL_PATH
                    },
                    "capture_metrics": {
                        "interface": NETWORK_INTERFACE,
                        "duration_seconds": CAPTURE_DURATION.total_seconds(),
                        "total_packets": len(self.packets)
                    },
                    "verification_metrics": self._generate_verification_metrics(),
                    "analysis_window": ANALYSIS_WINDOW.total_seconds()
                }

                # Save to log file
                self.logger.log_result(log_entry)

                print("Classification complete. Results logged to {0}".format(RESULTS_FILE))
                print("Prediction: {0} ({1:.2%} confidence)".format(
                    prediction,
                    conf.item()
                ))

        except Exception as e:
            error_entry = {
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "stack_trace": traceback.format_exc()
            }
            self.logger.log_result(error_entry)
            logging.error("Classification failed: {0}".format(str(e)))
            raise


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    try:
        classifier = LiveQUICClassifier()
        classifier.classify_and_log()
    except Exception as e:
        logging.error("Fatal error: {0}".format(str(e)))
        sys.exit(1)