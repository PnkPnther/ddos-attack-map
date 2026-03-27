import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

print("--- 🏭 STARTING THE FACTORY (LITE VERSION) 🏭 ---")

# 1. LOAD DATA
print("Loading Parquet file...")
# Make sure this path points to your actual data folder!
df = pd.read_parquet('data/Syn-training.parquet')  
df.columns = df.columns.str.strip()

# 2. THE LITE UPGRADE (Feature Selection)
print("Dropping 75 columns... Keeping only 'Avg Packet Size' and 'ACK Flag Count'...")
features_to_keep = ['Avg Packet Size', 'ACK Flag Count', 'Label']
df = df[[col for col in features_to_keep if col in df.columns]]

# 3. PREPARE THE DATA
X = df.drop(columns=['Label'])
y = df['Label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)

# Clean up any weird math errors (like dividing by zero)
X = X.replace([float('inf'), float('-inf')], 0).fillna(0)

# 4. SPLIT & TRAIN
print("Training the Lite Brain... (This will be lightning fast!)")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, max_depth=10, n_jobs=-1, random_state=42, class_weight='balanced')
model.fit(X_train, y_train)

# 5. TEST & SAVE
predictions = model.predict(X_test)
print(f"\n✅ Lite Model Accuracy: {accuracy_score(y_test, predictions) * 100:.2f}%")

joblib.dump(model, 'ddos_detector_lite_model.pkl')
print("✅ Brain successfully saved as 'ddos_detector_model.pkl'!")