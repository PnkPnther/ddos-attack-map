import pyshark
import time
from collections import defaultdict
import joblib
import pandas as pd
import numpy as np  # 🚨 NEW: Needed for Log Scaling

# ---------------------------------------------------------
# 1. LOAD THE AI BRAIN & SCALER
# ---------------------------------------------------------
print("Loading the Production AI Brain...")
try:
    # We now load TWO files: the model and the mathematical scaler
    model = joblib.load('models/pro_ddos_model.pkl') 
    scaler = joblib.load('models/pro_scaler.pkl')
    print("✅ System loaded successfully!\n")
except FileNotFoundError:
    print("❌ Error: Could not find model files in 'models/' folder.")
    exit()

# ---------------------------------------------------------
# 2. SET UP THE SENSORS
# ---------------------------------------------------------
def new_ip_record():
    return {'total_packets': 0, 'total_bytes': 0, 'ack_flags': 0}

traffic_stats = defaultdict(new_ip_record)
interface = 'lo'

print(f"--- 🛡️ PRO-LEVEL DDOS DETECTOR ACTIVE ON {interface} 🛡️ ---")
print("Waiting for traffic... (Press Ctrl+C to stop)")

capture = pyshark.LiveCapture(interface=interface)
start_time = time.time()

try:
    for packet in capture.sniff_continuously():
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            packet_length = int(packet.length)
            
            traffic_stats[src_ip]['total_packets'] += 1
            traffic_stats[src_ip]['total_bytes'] += packet_length
            
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags_ack'):
                if packet.tcp.flags_ack == '1':
                    traffic_stats[src_ip]['ack_flags'] += 1

        # Check the 10-second stopwatch (Upgraded for stealth detection)
        current_time = time.time()
        if current_time - start_time >= 10.0:
            
            if traffic_stats:
                print(f"\n--- 🕵️ Deep Analysis Window ({time.strftime('%H:%M:%S')}) ---")
                
                for ip, stats in traffic_stats.items():
                    avg_size = stats['total_bytes'] / stats['total_packets']
                    ack_flags = stats['ack_flags']
                    pps = stats['total_packets'] / 10.0 
                    
                    # 🚨 THE PRODUCTION PIPELINE 🚨
                    
                    # 1. Transform Speed using Log Scaling (matches training)
                    log_pps = np.log1p(pps)
                    
                    # 2. Package data for the Scaler
                    live_features = pd.DataFrame({
                        'Avg Packet Size': [avg_size],
                        'ACK Flag Count': [ack_flags],
                        'Flow Packets/s': [log_pps]
                    })
                    
                    # 3. Scale the data (Translates raw numbers to AI-readable format)
                    scaled_features = scaler.transform(live_features)
                    
                    # 4. Get Probability (Is it an attack? 0.0 to 1.0)
                    # [0][1] gives the probability of being DDoS (Label 1)
                    prob = model.predict_proba(scaled_features)[0][1]
                    
                    # 5. VERDICT: If confidence is > 30%, sound the alarm!
                    # (We use 0.3 because stealth attacks have subtle patterns)
                    if prob > 0.3:
                        print(f"🚨 DDOS DETECTED: {ip} 🚨 (Confidence: {prob*100:.1f}%)")
                    else:
                        print(f"✅ NORMAL: {ip} (Confidence: {(1-prob)*100:.1f}%)")
            
            traffic_stats.clear()
            start_time = time.time()

except KeyboardInterrupt:
    print("\nDetector shut down gracefully.")
except Exception as e:
    import traceback
    traceback.print_exc()