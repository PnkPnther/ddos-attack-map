import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib

print("--- 🚀 TRAINING THE PRODUCTION-GRADE BRAIN 🚀 ---")

# 1. LOAD DATA
df = pd.read_parquet('data/Syn-training.parquet')
df.columns = df.columns.str.strip()

# 2. FEATURE ENGINEERING: Focus on "DNA", not just "Speed"
# We add 'Size Std' to see if packets are "Robotic" (identical sizes)
features = ['Avg Packet Size', 'ACK Flag Count', 'Flow Packets/s']
X = df[features].replace([np.inf, -np.inf], 0).fillna(0)
y = df['Label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)

# 3. DATA AUGMENTATION: The "Stealth Hack"
# We take 20% of the DDoS rows and manually set their speed to be "Low and Slow"
# This teaches the AI that 0.1 pkt/s can still be a DDoS!
ddos_indices = y[y == 1].index
slow_indices = np.random.choice(ddos_indices, size=int(len(ddos_indices)*0.2), replace=False)
X.loc[slow_indices, 'Flow Packets/s'] = np.random.uniform(0.1, 1.0, size=len(slow_indices))

# 4. LOG SCALING: Make 0.1 as mathematically "loud" as 1000
X['Flow Packets/s'] = np.log1p(X['Flow Packets/s'])

# 5. STANDARDIZATION: Bring everything to a common scale (0 to 1 range)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 6. TRAIN A DEEPER FOREST
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=250, max_depth=20, class_weight='balanced', n_jobs=-1)
model.fit(X_train, y_train)

# 7. SAVE THE BRAIN AND THE SCALER (Crucial!)
joblib.dump(model, 'models/pro_ddos_model.pkl')
joblib.dump(scaler, 'models/pro_scaler.pkl') 

print("✅ Professional Model & Scaler saved!")