import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

# STEP 1: LOAD THE DATA
print("Loading data from Syn-training.parquet...")
df = pd.read_parquet('data/Syn-training.parquet')

# STEP 2: PREPROCESS (CLEANING)
print("Cleaning data and removing 'cheat' columns...")
df.columns = df.columns.str.strip()

# We drop columns that let the model cheat (Data Leakage)
columns_to_drop = [
    'Unnamed: 0', 'Flow ID', 'Source IP', 'Destination IP', 
    'Timestamp', 'SimillarHTTP', 'Label', 'Inbound'
]
X = df.drop(columns=[col for col in columns_to_drop if col in df.columns], errors='ignore')

# Convert labels: 0 for normal traffic, 1 for attacks
y = df['Label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)

# Math algorithms crash if they see "Infinity" or "NaN" (Not a Number), so we replace them with 0
X = X.replace([float('inf'), float('-inf')], 0).fillna(0)

# STEP 3: SPLIT THE DATA
print("Splitting data into 80% training and 20% testing...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# STEP 4: TRAIN THE MODEL
print("Training the Random Forest... (this takes a few seconds)")
# class_weight='balanced' forces the model to care equally about safe traffic and attacks
model = RandomForestClassifier(n_estimators=100, max_depth=10, n_jobs=-1, random_state=42, class_weight='balanced')
model.fit(X_train, y_train)

# STEP 5: EVALUATE & SAVE
print("Taking the final exam...")
predictions = model.predict(X_test)

print(f"\n--- FINAL RESULTS ---")
print(f"Accuracy: {accuracy_score(y_test, predictions) * 100:.2f}%")
print(classification_report(y_test, predictions, target_names=['Benign (0)', 'DDoS (1)']))

joblib.dump(model, 'ddos_detector_model.pkl')
print("Model successfully saved as 'ddos_detector_model.pkl'!")