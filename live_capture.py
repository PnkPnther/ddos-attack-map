import pyshark
import time
from collections import defaultdict

# We use a helper function to create a blank scorecard for any new IP we see
def new_ip_record():
    return {'total_packets': 0, 'total_bytes': 0, 'ack_flags': 0}

# This dictionary will group our traffic by Source IP
# Format: { '192.168.1.5': {'total_packets': 5, ...} }
traffic_stats = defaultdict(new_ip_record)

interface = 'eth0' # Default WSL network interface
print(f"--- ACTIVE SNIFFER STARTED ON {interface} ---")
print("Waiting for traffic... (Press Ctrl+C to stop)")

# Start capturing live traffic
capture = pyshark.LiveCapture(interface=interface)
start_time = time.time()

try:
    # sniff_continuously() is an infinite loop that yields packets as they arrive
    for packet in capture.sniff_continuously():
        
        # 1. PARSE THE PACKET
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            
            # Pyshark reads length as a string, so we convert to integer
            packet_length = int(packet.length) 
            
            # Update the basic stats for this IP
            traffic_stats[src_ip]['total_packets'] += 1
            traffic_stats[src_ip]['total_bytes'] += packet_length
            
            # Check for TCP ACK flags (since we know your model loves this feature!)
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags_ack'):
                if packet.tcp.flags_ack == '1':
                    traffic_stats[src_ip]['ack_flags'] += 1

        # 2. CHECK THE TIMER (The 2-Second Rolling Window)
        current_time = time.time()
        if current_time - start_time >= 2.0:
            
            # Only print if we actually caught something in the last 2 seconds
            if traffic_stats:
                print(f"\n--- Traffic Summary (Last 2 Seconds) ---")
                
                # 3. CALCULATE ROLLING STATISTICS
                for ip, stats in traffic_stats.items():
                    avg_size = stats['total_bytes'] / stats['total_packets']
                    
                    print(f"Source IP: {ip}")
                    print(f"  -> Packets: {stats['total_packets']}")
                    print(f"  -> Avg Size: {avg_size:.1f} bytes")
                    print(f"  -> ACK Flags: {stats['ack_flags']}")
            
            # 4. RESET THE WINDOW
            traffic_stats.clear()
            start_time = time.time()

except KeyboardInterrupt:
    print("\nCapture stopped by user. Shutting down gracefully.")
except Exception as e:
    print(f"\nAn error occurred: {e}")
