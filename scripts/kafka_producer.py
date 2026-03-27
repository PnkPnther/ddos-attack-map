import pyshark
from kafka import KafkaProducer
import json

# Set up the Kafka producer
producer = KafkaProducer(
    bootstrap_servers=["localhost:9092"],
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

# Network interface to listen on
# Change to "eth0" to listen to 
interface = "lo"
print(f"Streaming traffic from {interface} to Kafka...")

# Ignore Kafka traffic so the script does not capture its own messages
capture = pyshark.LiveCapture(
    interface=interface,
    display_filter="not tcp.port == 9092"
)

for packet in capture.sniff_continuously():
    try:
        # Only process packets that have IP data
        if hasattr(packet, "ip"):
            data = {
                "src_ip": packet.ip.src,
                "length": int(packet.length),
                "timestamp": float(packet.sniff_timestamp),
                "is_ack": 1 if (
                    hasattr(packet, "tcp")
                    and hasattr(packet.tcp, "flags_ack")
                    and packet.tcp.flags_ack == "1"
                ) else 0
            }

            # Send the packet data to Kafka
            producer.send("network-traffic", value=data)

    except:
        continue