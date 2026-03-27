import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
import joblib
import os

# Make sure the models folder exists before saving anything
if not os.path.exists("models"):
    os.makedirs("models")

print("Starting anomaly model training...")

# Load the training data
# This uses the parquet file you already have in the data folder
try:
    df = pd.read_parquet("data/Syn-training.parquet")
    df.columns = df.columns.str.strip()
    print("Training data loaded successfully.")
except Exception as e:
    print(f"Could not load the training data: {e}")
    exit()

# Keep only normal traffic
# The model learns what normal looks like, then flags anything unusual
benign_df = df[df["Label"].str.upper() == "BENIGN"].copy()

# Pick the features we want to train on
features = ["Avg Packet Size", "ACK Flag Count", "Flow Packets/s"]
X = benign_df[features].replace([np.inf, -np.inf], 0).fillna(0)

print("Normal traffic filtered and features selected.")

# Scale the data
# RobustScaler works well when the data has spikes or outliers
scaler = RobustScaler()
X_scaled = scaler.fit_transform(X)

print("Feature scaling complete.")

# Train the Isolation Forest model
# contamination is kept low since most of this data should be normal
model = IsolationForest(
    n_estimators=200,
    contamination=0.01,
    random_state=42
)
model.fit(X_scaled)

print("Model training complete.")

# Save both the trained model and scaler for later use
joblib.dump(model, "models/anomaly_watchman.pkl")
joblib.dump(scaler, "models/robust_scaler.pkl")

print("Saved the model and scaler in the models folder.")