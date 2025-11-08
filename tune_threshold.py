"""
Threshold Tuning for CICIDS-2018 Detection
Adjusts classification threshold to improve attack detection
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_curve
import matplotlib.pyplot as plt

print("=" * 60)
print("Threshold Tuning for Attack Detection")
print("=" * 60)

# Load CICIDS-2018 data
print("\nLoading CICIDS-2018 dataset...")
df = pd.read_csv('02-14-2018.csv')
df.columns = df.columns.str.strip()

print(f"Dataset shape: {df.shape}")
print(f"\nActual label distribution:")
print(df['Label'].value_counts())

# Apply column mapping
column_mapping = {
    'ACK Flag Cnt': 'ACK Flag Count',
    'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',
    'Bwd Byts/b Avg': 'Bwd Avg Bytes/Bulk',
    'Bwd Header Len': 'Bwd Header Length',
    'Bwd IAT Tot': 'Bwd IAT Total',
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

# Prepare features
scaler = joblib.load('models/scaler.pkl')
model = joblib.load('models/xgboost_model.pkl')

expected_features = scaler.feature_names_in_.tolist()

cols_to_drop = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 
                'Destination Port', 'Protocol', 'Timestamp', 'Label']
cols_to_drop = [col for col in cols_to_drop if col in df.columns]

# Create binary labels (0=Benign, 1=Attack)
y_true = (df['Label'] != 'Benign').astype(int)

X = df.drop(columns=cols_to_drop, errors='ignore')

for feature in expected_features:
    if feature not in X.columns:
        X[feature] = 0

X = X[expected_features]
X.replace([np.inf, -np.inf], 0, inplace=True)
X.fillna(0, inplace=True)

print("\nScaling features...")
X_scaled = scaler.transform(X)

print("Getting model predictions...")
y_proba = model.predict_proba(X_scaled)[:, 1]  # Probability of attack class

print("\n" + "=" * 60)
print("Threshold Analysis")
print("=" * 60)

# Test different thresholds
thresholds_to_test = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]

results = []
for threshold in thresholds_to_test:
    y_pred = (y_proba >= threshold).astype(int)
    
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    attacks_detected = int(np.sum(y_pred))
    
    results.append({
        'threshold': threshold,
        'attacks_detected': attacks_detected,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'tp': tp,
        'fp': fp,
        'tn': tn,
        'fn': fn
    })
    
    print(f"\nThreshold: {threshold:.1f}")
    print(f"  Attacks detected: {attacks_detected:,} ({attacks_detected/len(y_true)*100:.1f}%)")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1-Score:  {f1:.4f}")
    print(f"  TP: {tp:,}  FP: {fp:,}  TN: {tn:,}  FN: {fn:,}")

# Find best threshold based on F1-score
best_result = max(results, key=lambda x: x['f1_score'])
print("\n" + "=" * 60)
print("RECOMMENDED THRESHOLD")
print("=" * 60)
print(f"Best threshold: {best_result['threshold']:.1f}")
print(f"This will detect {best_result['attacks_detected']:,} attacks ({best_result['attacks_detected']/len(y_true)*100:.1f}%)")
print(f"Accuracy:  {best_result['accuracy']:.4f}")
print(f"Precision: {best_result['precision']:.4f}")
print(f"Recall:    {best_result['recall']:.4f}")
print(f"F1-Score:  {best_result['f1_score']:.4f}")

# Save optimal threshold
optimal_threshold = best_result['threshold']
with open('models/optimal_threshold.txt', 'w') as f:
    f.write(str(optimal_threshold))

print(f"\n✓ Optimal threshold ({optimal_threshold}) saved to models/optimal_threshold.txt")

# Create visualization
print("\nGenerating threshold comparison chart...")
fig, axes = plt.subplots(2, 2, figsize=(14, 10))
fig.suptitle('Threshold Tuning Analysis', fontsize=16, fontweight='bold')

thresholds = [r['threshold'] for r in results]

# Plot 1: Accuracy, Precision, Recall, F1
ax = axes[0, 0]
ax.plot(thresholds, [r['accuracy'] for r in results], 'o-', label='Accuracy', linewidth=2)
ax.plot(thresholds, [r['precision'] for r in results], 's-', label='Precision', linewidth=2)
ax.plot(thresholds, [r['recall'] for r in results], '^-', label='Recall', linewidth=2)
ax.plot(thresholds, [r['f1_score'] for r in results], 'd-', label='F1-Score', linewidth=2)
ax.axvline(x=optimal_threshold, color='red', linestyle='--', alpha=0.7, label=f'Optimal ({optimal_threshold})')
ax.set_xlabel('Threshold', fontsize=12)
ax.set_ylabel('Score', fontsize=12)
ax.set_title('Performance Metrics vs Threshold', fontsize=13, fontweight='bold')
ax.legend()
ax.grid(True, alpha=0.3)

# Plot 2: Attacks Detected
ax = axes[0, 1]
ax.plot(thresholds, [r['attacks_detected'] for r in results], 'o-', linewidth=2, color='darkblue')
ax.axvline(x=optimal_threshold, color='red', linestyle='--', alpha=0.7, label=f'Optimal ({optimal_threshold})')
ax.axhline(y=len(y_true[y_true==1]), color='green', linestyle='--', alpha=0.7, label='Actual Attacks')
ax.set_xlabel('Threshold', fontsize=12)
ax.set_ylabel('Number of Attacks Detected', fontsize=12)
ax.set_title('Detection Count vs Threshold', fontsize=13, fontweight='bold')
ax.legend()
ax.grid(True, alpha=0.3)

# Plot 3: Precision-Recall Curve
ax = axes[1, 0]
precision_curve, recall_curve, thresholds_curve = precision_recall_curve(y_true, y_proba)
ax.plot(recall_curve, precision_curve, linewidth=2, color='purple')
ax.set_xlabel('Recall', fontsize=12)
ax.set_ylabel('Precision', fontsize=12)
ax.set_title('Precision-Recall Curve', fontsize=13, fontweight='bold')
ax.grid(True, alpha=0.3)

# Plot 4: Confusion Matrix for Optimal Threshold
ax = axes[1, 1]
cm = np.array([[best_result['tn'], best_result['fp']], 
               [best_result['fn'], best_result['tp']]])
im = ax.imshow(cm, cmap='Blues')
ax.set_xticks([0, 1])
ax.set_yticks([0, 1])
ax.set_xticklabels(['Benign', 'Attack'])
ax.set_yticklabels(['Benign', 'Attack'])
ax.set_xlabel('Predicted', fontsize=12)
ax.set_ylabel('Actual', fontsize=12)
ax.set_title(f'Confusion Matrix (Threshold={optimal_threshold})', fontsize=13, fontweight='bold')

for i in range(2):
    for j in range(2):
        text = ax.text(j, i, f'{cm[i, j]:,}',
                      ha="center", va="center", color="white" if cm[i, j] > cm.max()/2 else "black",
                      fontsize=14, fontweight='bold')

plt.tight_layout()
plt.savefig('threshold_analysis.png', dpi=150, bbox_inches='tight')
print("✓ Chart saved to threshold_analysis.png")

print("\n" + "=" * 60)
print("To apply this threshold in your Flask app:")
print(f"1. Open app.py")
print(f"2. Find: y_pred = (y_pred_proba > 0.5)")
print(f"3. Change to: y_pred = (y_pred_proba > {optimal_threshold})")
print("=" * 60)
