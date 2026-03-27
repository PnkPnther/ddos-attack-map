import joblib
import pandas as pd
import matplotlib.pyplot as plt

# 1. Load the model we saved in Phase 1
model = joblib.load('ddos_detector_model.pkl')

# 2. Get the feature names (we need to match them back to the importance scores)
# We'll grab them from the training file again to be sure
df = pd.read_parquet('data/Syn-training.parquet')
df.columns = df.columns.str.strip()
columns_to_drop = [
    'Unnamed: 0', 'Flow ID', 'Source IP', 'Destination IP', 
    'Timestamp', 'SimillarHTTP', 'Label', 'Inbound'
]
feature_names = df.drop(columns=[col for col in columns_to_drop if col in df.columns], errors='ignore').columns

# 3. Extract the importance scores
importances = model.feature_importances_

# 4. Organize them into a nice table
feature_results = pd.DataFrame({'Feature': feature_names, 'Importance': importances})
feature_results = feature_results.sort_values(by='Importance', ascending=False)

# 5. Print the Top 10
print("\n--- TOP 10 MOST IMPORTANT FEATURES ---")
print(feature_results.head(10))

