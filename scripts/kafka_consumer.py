from kafka import KafkaConsumer
import json
import joblib
import pandas as pd
import numpy as np
from collections import defaultdict
import time

# Load the trained anomaly detection model and scaler
# The model checks whether traffic looks unusual
# The scaler makes sure the incoming values are transformed the same way as during training
print("Loading anomaly detection model...")
model = joblib.load("models/anomaly_watchman.pkl")
scaler = joblib.load("models/robust_scaler.pkl")

# Create the Kafka consumer
# This listens to the network-traffic topic where packet summaries are being sent
# auto_offset_reset is set to latest so it only reads new messages coming in now
# Change it to earliest if you want to process older messages already sitting in the topic
consumer = KafkaConsumer(
    "network-traffic",
    bootstrap_servers=["localhost:9092"],
    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
    auto_offset_reset="latest"
)

# Create a fresh stats record for each source IP
# This keeps track of packet count, total bytes, ACK flags, timing between packets,
# and the timestamp of the last packet seen from that IP
def new_ip_record():
    return {
        "total_packets": 0,
        "total_bytes": 0,
        "ack_flags": 0,
        "last_timestamp": None,
        "iat_list": []
    }

# Store traffic statistics grouped by source IP
# defaultdict automatically creates a blank record the first time a new IP appears
traffic_stats = defaultdict(new_ip_record)

# Set the analysis window length
# Every 10 seconds, the script stops and evaluates the traffic collected so far
analysis_window = 10.0
start_time = time.time()

print("Consumer is running and watching the Kafka stream...")

# Main loop
# poll() is used instead of a simple for-loop so the timer can still be checked regularly even during periods where traffic is slow or inconsistent
while True:
    msg_pack = consumer.poll(timeout_ms=500)

    # Go through all messages returned by Kafka during this poll cycle
    for tp, messages in msg_pack.items():
        for message in messages:
            pkt = message.value
            ip = pkt["src_ip"]

            # Update the running stats for this source IP
            # This builds the traffic profile that will be analyzed at the end of the window
            stats = traffic_stats[ip]
            stats["total_packets"] += 1
            stats["total_bytes"] += pkt["length"]

            # Calculate inter-arrival time
            # This measures the time gap between packets from the same IP
            # Very consistent gaps can be a sign of automated or scripted traffic
            if stats["last_timestamp"] is not None:
                iat = pkt["timestamp"] - stats["last_timestamp"]
                stats["iat_list"].append(iat)

            # Save this packet's timestamp so the next gap can be calculated
            stats["last_timestamp"] = pkt["timestamp"]

            # Count how many packets had the ACK flag set
            # This is one of the features used by the anomaly model
            if pkt["is_ack"] == 1:
                stats["ack_flags"] += 1

    # Once the analysis window has passed, evaluate all collected traffic
    if time.time() - start_time >= analysis_window:
        if traffic_stats:
            print(f"\nAnalysis window at {time.strftime('%H:%M:%S')}")

            # Cluster check
            # This looks for repeated average packet sizes across many different IPs
            # If a lot of IPs are sending packets with nearly the same small average size,
            # that can suggest coordinated attack traffic
            size_counts = defaultdict(int)
            for ip, s in traffic_stats.items():
                if s["total_packets"] > 0:
                    rounded_size = round(s["total_bytes"] / s["total_packets"], 1)
                    size_counts[rounded_size] += 1

            suspicious_sizes = [
                sz for sz, count in size_counts.items()
                if count > 5 and sz < 100
            ]

            # Analyze each IP separately using the model and rule-based checks
            for ip, stats in list(traffic_stats.items()):
                # Calculate summary values for this IP over the current window
                avg_size = stats["total_bytes"] / stats["total_packets"]
                pps = stats["total_packets"] / analysis_window

                # Build the input row for the anomaly model
                # These are the same features used when the model was trained
                raw_data = pd.DataFrame({
                    "Avg Packet Size": [avg_size],
                    "ACK Flag Count": [stats["ack_flags"]],
                    "Flow Packets/s": [pps]
                })

                # Scale the data first, then get the model's prediction
                # A result of -1 means the traffic looks abnormal
                prediction = model.predict(scaler.transform(raw_data))[0]

                # Robotic timing check
                # If the packet timing variance is very low, the traffic may be too regular
                # to be natural, especially if enough packets were seen
                iat_variance = np.var(stats["iat_list"]) if len(stats["iat_list"]) > 1 else 1.0
                is_robotic = iat_variance < 0.005 and stats["total_packets"] > 3

                # Cluster pattern check
                # If this IP matches one of the suspicious repeated packet-size groups,
                # and it is not local loopback traffic, flag it as suspicious
                is_in_cluster = round(avg_size, 1) in suspicious_sizes and not ip.startswith("127.")

                # Final decision
                # Traffic is flagged if any one of the checks says it looks suspicious
                if prediction == -1 or is_robotic or is_in_cluster:
                    if prediction == -1:
                        reason = "AI outlier"
                    elif is_robotic:
                        reason = "robotic timing"
                    else:
                        reason = "cluster pattern"

                    print(f"ALERT: Possible DDoS from {ip} | Reason: {reason} | Size: {avg_size:.1f}b")
                else:
                    print(f"Normal traffic: {ip} | Size: {avg_size:.1f}b | PPS: {pps:.1f}")

            # Clear all saved traffic stats so the next 10-second window starts fresh
            traffic_stats.clear()

        # Reset the timer for the next analysis window
        start_time = time.time()