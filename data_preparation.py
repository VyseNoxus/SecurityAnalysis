"""
CICIDS Dataset Preparation Script
Data Split: 60% training, 20% test seen, 20% test unseen
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import os

# Can use single dataset or combine multiple
DATASET_PATHS = [
    "Tuesday-WorkingHours.pcap_ISCX.csv",  # CICIDS-2017
]
OUTPUT_DIR = "data/processed"
RANDOM_STATE = 42

os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=" * 60)
print("CICIDS Dataset Preparation")
print("=" * 60)

print(f"\n1. Loading datasets...")
dfs = []
for dataset_path in DATASET_PATHS:
    if os.path.exists(dataset_path):
        print(f"   Loading {dataset_path}...")
        temp_df = pd.read_csv(dataset_path)
        temp_df.columns = temp_df.columns.str.strip()
        print(f"     Shape: {temp_df.shape[0]:,} rows × {temp_df.shape[1]} columns")
        dfs.append(temp_df)
    else:
        print(f"   ⚠ Skipping {dataset_path} (not found)")

if not dfs:
    raise FileNotFoundError("No dataset files found!")

print(f"\n   Combining {len(dfs)} dataset(s)...")
df = pd.concat(dfs, ignore_index=True)
print(f"\n   Combined shape: {df.shape[0]:,} rows × {df.shape[1]} columns")

print("\n2. Normalizing label names...")
# Standardize label capitalization (2017 uses BENIGN, 2018 uses Benign)
df['Label'] = df['Label'].str.strip()
df['Label'] = df['Label'].replace('Benign', 'BENIGN')

print("\n3. Label Distribution:")
print(df['Label'].value_counts())

print("\n4. Handling missing values...")
missing = df.isnull().sum().sum()
if missing > 0:
    print(f"   Filling {missing} missing values with 0")
    df.fillna(0, inplace=True)
else:
    print("   No missing values")

print("\n5. Handling infinite values...")
inf_cols = []
for col in df.select_dtypes(include=[np.number]).columns:
    if np.isinf(df[col]).any():
        inf_cols.append(col)
        df[col].replace([np.inf, -np.inf], 0, inplace=True)
if inf_cols:
    print(f"   Fixed {len(inf_cols)} columns")
else:
    print("   No infinite values")

print("\n6. Removing duplicates...")
initial_rows = len(df)
df.drop_duplicates(inplace=True)
print(f"   Removed {initial_rows - len(df):,} duplicates")

print("\n7. Creating 60/20/20 split...")
train_df, test_df = train_test_split(
    df, test_size=0.4, stratify=df['Label'], random_state=RANDOM_STATE
)

test_benign = test_df[test_df['Label'] == 'BENIGN']
test_attacks = test_df[test_df['Label'] != 'BENIGN']

if len(test_attacks) > 0:
    test_seen, test_unseen = train_test_split(
        test_attacks, test_size=0.5, stratify=test_attacks['Label'], random_state=RANDOM_STATE
    )
    test_seen_final = pd.concat([test_benign, test_seen], ignore_index=True)
    test_unseen_final = test_unseen
else:
    test_seen_final = test_benign
    test_unseen_final = pd.DataFrame()

print(f"   Training: {len(train_df):,} samples")
print(f"   Test Seen: {len(test_seen_final):,} samples")
print(f"   Test Unseen: {len(test_unseen_final):,} samples")

print("\n8. Saving datasets...")
train_df.to_csv(f"{OUTPUT_DIR}/train.csv", index=False)
test_seen_final.to_csv(f"{OUTPUT_DIR}/test_seen.csv", index=False)
test_unseen_final.to_csv(f"{OUTPUT_DIR}/test_unseen.csv", index=False)
test_df.to_csv(f"{OUTPUT_DIR}/test_full.csv", index=False)
print("   ✓ All datasets saved")

print("\n" + "=" * 60)
print("Dataset preparation complete!")
print("=" * 60)
