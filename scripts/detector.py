#-----------------------------------------------------------------------------
# OLD DETECTOR
#-----------------------------------------------------------------------------

import pyshark
import time
from collections import defaultdict
import joblib
import pandas as pd
import numpy as np

# Load the saved model and scaler
print("Loading anomaly detection system...")

try:
    model = joblib.load("models/anomaly_watchman.pkl")
    scaler = joblib.load("models/robust_scaler.pkl")
    print("System loaded.\n")
except FileNotFoundError:
    print("Model files not found. Run the training script first.")
    exit()


# Create a blank stats record for each source IP
def new_ip_record():
    return {
        "total_packets": 0,
        "total_bytes": 0,
        "ack_flags": 0,
        "last_timestamp": None,
        "iat_list": []
    }


# Store live traffic stats grouped by source IP
traffic_stats = defaultdict(new_ip_record)

# Capture settings
interface = "lo"
analysis_window = 10.0

print(f"IDS is running on interface {interface}.")

# Start live packet capture
capture = pyshark.LiveCapture(interface=interface)
start_time = time.time()

try:
    for packet in capture.sniff_continuously():
        # Only process packets that have IP information
        if hasattr(packet, "ip"):
            src_ip = packet.ip.src
            pkt_len = int(packet.length)
            pkt_time = float(packet.sniff_timestamp)

            stats = traffic_stats[src_ip]
            stats["total_packets"] += 1
            stats["total_bytes"] += pkt_len

            # Track time gaps between packets for timing analysis
            if stats["last_timestamp"] is not None:
                iat = pkt_time - stats["last_timestamp"]
                stats["iat_list"].append(iat)

            stats["last_timestamp"] = pkt_time

            # Count ACK flags for TCP traffic
            if hasattr(packet, "tcp") and hasattr(packet.tcp, "flags_ack"):
                if packet.tcp.flags_ack == "1":
                    stats["ack_flags"] += 1

        # Run analysis once every set time window
        if time.time() - start_time >= analysis_window:
            if traffic_stats:
                print(f"\nAnalysis window at {time.strftime('%H:%M:%S')}")

                # Count how many different IPs share the same average packet size
                size_counts = defaultdict(int)
                for ip, s in traffic_stats.items():
                    if s["total_packets"] > 0:
                        rounded_size = round(s["total_bytes"] / s["total_packets"], 1)
                        size_counts[rounded_size] += 1

                # Mark packet sizes as suspicious if too many IPs share them
                suspicious_sizes = [
                    sz for sz, count in size_counts.items()
                    if count > 5 and sz < 100
                ]

                for ip, stats in list(traffic_stats.items()):
                    if stats["total_packets"] == 0:
                        continue

                    avg_size = stats["total_bytes"] / stats["total_packets"]
                    pps = stats["total_packets"] / analysis_window

                    # Build input for the model
                    raw_data = pd.DataFrame({
                        "Avg Packet Size": [avg_size],
                        "ACK Flag Count": [stats["ack_flags"]],
                        "Flow Packets/s": [pps]
                    })

                    scaled_data = scaler.transform(raw_data)
                    prediction = model.predict(scaled_data)[0]

                    # Check for very consistent packet timing
                    iat_variance = np.var(stats["iat_list"]) if len(stats["iat_list"]) > 1 else 1.0
                    is_robotic = iat_variance < 0.005 and stats["total_packets"] > 3

                    # Check if this IP matches a suspicious traffic cluster
                    is_in_cluster = round(avg_size, 1) in suspicious_sizes and not ip.startswith("127.")

                    # Final decision
                    if prediction == -1 or is_robotic or is_in_cluster:
                        if prediction == -1:
                            reason = "AI outlier"
                        elif is_robotic:
                            reason = "robotic timing"
                        else:
                            reason = "cluster pattern"

                        print(f"ALERT: possible DDoS from {ip} | Reason: {reason} | Size: {avg_size:.1f}b")
                    else:
                        print(f"Normal traffic: {ip} | Size: {avg_size:.1f}b | PPS: {pps:.1f}")

            # Reset stats for the next window
            traffic_stats.clear()
            start_time = time.time()

except KeyboardInterrupt:
    print("\nIDS stopped.")
except Exception as e:
    import traceback
    traceback.print_exc()