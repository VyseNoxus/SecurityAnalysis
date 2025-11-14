"""Quick diagnostic to test XGBoost detection on CICIDS-2018"""
import pandas as pd
import numpy as np
import joblib

# Load data
df = pd.read_csv('02-14-2018.csv')
df.columns = df.columns.str.strip()
print(f"Total samples: {len(df):,}")
print(f"\nTrue labels:\n{df['Label'].value_counts()}")

# Column mapping (same as app.py)
column_mapping = {
    'ACK Flag Cnt': 'ACK Flag Count',
    'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',
    'Bwd Byts/b Avg': 'Bwd Avg Bytes/Bulk',
    'Bwd Header Len': 'Bwd Header Length',
    'Bwd Pkt Len Max': 'Bwd Packet Length Max',
    'Bwd Pkt Len Mean': 'Bwd Packet Length Mean',
    'Bwd Pkt Len Min': 'Bwd Packet Length Min',
    'Bwd Pkt Len Std': 'Bwd Packet Length Std',
    'Bwd Pkts/b Avg': 'Bwd Avg Packets/Bulk',
    'Bwd Pkts/s': 'Bwd Packets/s',
    'Bwd Seg Size Avg': 'Avg Bwd Segment Size',
    'ECE Flag Cnt': 'ECE Flag Count',
    'FIN Flag Cnt': 'FIN Flag Count',
    'Flow Byts/s': 'Flow Bytes/s',
    'Flow Pkts/s': 'Flow Packets/s',
    'Fwd Act Data Pkts': 'act_data_pkt_fwd',
    'Fwd Blk Rate Avg': 'Fwd Avg Bulk Rate',
    'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',
    'Fwd Header Len': 'Fwd Header Length',
    'Fwd IAT Tot': 'Fwd IAT Total',
    'Fwd Pkt Len Max': 'Fwd Packet Length Max',
    'Fwd Pkt Len Mean': 'Fwd Packet Length Mean',
    'Fwd Pkt Len Min': 'Fwd Packet Length Min',
    'Fwd Pkt Len Std': 'Fwd Packet Length Std',
    'Fwd Pkts/b Avg': 'Fwd Avg Packets/Bulk',
    'Fwd Pkts/s': 'Fwd Packets/s',
    'Fwd Seg Size Avg': 'Avg Fwd Segment Size',
    'Fwd Seg Size Min': 'min_seg_size_forward',
    'Init Fwd Win Byts': 'Init_Win_bytes_forward',
    'Init Bwd Win Byts': 'Init_Win_bytes_backward',
    'Pkt Len Max': 'Max Packet Length',
    'Pkt Len Mean': 'Packet Length Mean',
    'Pkt Len Min': 'Min Packet Length',
    'Pkt Len Std': 'Packet Length Std',
    'Pkt Len Var': 'Packet Length Variance',
    'Pkt Size Avg': 'Average Packet Size',
    'PSH Flag Cnt': 'PSH Flag Count',
    'RST Flag Cnt': 'RST Flag Count',
    'SYN Flag Cnt': 'SYN Flag Count',
    'Bwd IAT Tot': 'Bwd IAT Total',
    'Subflow Bwd Byts': 'Subflow Bwd Bytes',
    'Subflow Bwd Pkts': 'Subflow Bwd Packets',
    'Subflow Fwd Byts': 'Subflow Fwd Bytes',
    'Subflow Fwd Pkts': 'Subflow Fwd Packets',
    'Tot Fwd Pkts': 'Total Fwd Packets',
    'Tot Bwd Pkts': 'Total Backward Packets',
    'TotLen Fwd Pkts': 'Total Length of Fwd Packets',
    'TotLen Bwd Pkts': 'Total Length of Bwd Packets',
    'URG Flag Cnt': 'URG Flag Count'
}

df = df.rename(columns=column_mapping)

# Load scaler and model
scaler = joblib.load('models/scaler.pkl')
model = joblib.load('models/xgboost_model.pkl')

# Prepare features
expected_features = scaler.feature_names_in_.tolist()
cols_to_drop = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 
                'Destination Port', 'Protocol', 'Timestamp', 'Label']
cols_to_drop = [col for col in cols_to_drop if col in df.columns]

true_labels = df['Label'].tolist()
X = df.drop(columns=cols_to_drop, errors='ignore')

# Add missing features
for feature in expected_features:
    if feature not in X.columns:
        X[feature] = 0

X = X[expected_features]
X.replace([np.inf, -np.inf], 0, inplace=True)
X.fillna(0, inplace=True)

X_scaled = scaler.transform(X)

# Predict with different thresholds
probabilities = model.predict_proba(X_scaled)[:, 1]

print(f"\nProbability statistics:")
print(f"  Min:    {probabilities.min():.6f}")
print(f"  Max:    {probabilities.max():.6f}")
print(f"  Mean:   {probabilities.mean():.6f}")
print(f"  Median: {np.median(probabilities):.6f}")

thresholds_to_test = [0.1, 0.5, 0.9895]
for thresh in thresholds_to_test:
    preds = (probabilities >= thresh).astype(int)
    attacks = np.sum(preds)
    print(f"\nThreshold {thresh}:")
    print(f"  Attacks detected: {attacks:,} ({attacks/len(preds)*100:.2f}%)")
    
    # Check by true label
    attack_mask = np.array([label != 'Benign' for label in true_labels])
    true_positives = np.sum(preds[attack_mask])
    false_positives = np.sum(preds[~attack_mask])
    print(f"  True positives: {true_positives:,}")
    print(f"  False positives: {false_positives:,}")
