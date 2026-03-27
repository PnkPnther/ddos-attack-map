import pandas as pd

# Load the testing data to keep it fast
df = pd.read_parquet('data/Syn-training.parquet')

print("--- Data Loaded Successfully ---")
print(f"Total Rows: {len(df)}")
print("\nAvailable Columns (Features):")
print(df.columns.tolist()[:10]) # Just showing the first 10