"""
Unified Threshold Calibration for XGBoost and LSTM
-------------------------------------------------
Calibrates decision threshold using F2 (recall-weighted) under a false positive rate constraint.

Supports:
  - XGBoost (per-row probabilities)
  - LSTM (sequence probabilities aggregated with 'any' attack rule, then expanded)

Outputs:
  - XGBoost threshold -> models/xgboost_threshold.pkl (also mirrors to models/optimal_threshold.txt for legacy use)
  - LSTM threshold    -> models/lstm_threshold.pkl   (also mirrors to models/optimal_threshold.txt if --write_optimal)

Examples (PowerShell):
  python tune_threshold.py -model xgboost -fp_max 0.005 -step 0.05
  python tune_threshold.py -model lstm    -fp_max 0.01  -step 0.02 --write_optimal
"""

import argparse
import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import confusion_matrix, precision_recall_curve
import matplotlib.pyplot as plt
import os

try:
    import tensorflow as tf  # Only needed for LSTM mode
except ImportError:
    tf = None

def load_and_prepare_dataframe(csv_path):
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    return df

def apply_column_mapping(df):
    column_mapping = {
        'ACK Flag Cnt': 'ACK Flag Count', 'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate', 'Bwd Byts/b Avg': 'Bwd Avg Bytes/Bulk',
        'Bwd Header Len': 'Bwd Header Length', 'Bwd IAT Tot': 'Bwd IAT Total', 'Bwd Pkt Len Max': 'Bwd Packet Length Max',
        'Bwd Pkt Len Mean': 'Bwd Packet Length Mean', 'Bwd Pkt Len Min': 'Bwd Packet Length Min', 'Bwd Pkt Len Std': 'Bwd Packet Length Std',
        'Bwd Pkts/b Avg': 'Bwd Avg Packets/Bulk', 'Bwd Pkts/s': 'Bwd Packets/s', 'Bwd Seg Size Avg': 'Avg Bwd Segment Size',
        'ECE Flag Cnt': 'ECE Flag Count', 'FIN Flag Cnt': 'FIN Flag Count', 'Flow Byts/s': 'Flow Bytes/s', 'Flow Pkts/s': 'Flow Packets/s',
        'Fwd Act Data Pkts': 'act_data_pkt_fwd', 'Fwd Blk Rate Avg': 'Fwd Avg Bulk Rate', 'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',
        'Fwd Header Len': 'Fwd Header Length', 'Fwd IAT Tot': 'Fwd IAT Total', 'Fwd Pkt Len Max': 'Fwd Packet Length Max',
        'Fwd Pkt Len Mean': 'Fwd Packet Length Mean', 'Fwd Pkt Len Min': 'Fwd Packet Length Min', 'Fwd Pkt Len Std': 'Fwd Packet Length Std',
        'Fwd Pkts/b Avg': 'Fwd Avg Packets/Bulk', 'Fwd Pkts/s': 'Fwd Packets/s', 'Fwd Seg Size Avg': 'Avg Fwd Segment Size',
        'Fwd Seg Size Min': 'min_seg_size_forward', 'Init Fwd Win Byts': 'Init_Win_bytes_forward', 'Init Bwd Win Byts': 'Init_Win_bytes_backward',
        'Pkt Len Max': 'Max Packet Length', 'Pkt Len Mean': 'Packet Length Mean', 'Pkt Len Min': 'Min Packet Length', 'Pkt Len Std': 'Packet Length Std',
        'Pkt Len Var': 'Packet Length Variance', 'Pkt Size Avg': 'Average Packet Size', 'PSH Flag Cnt': 'PSH Flag Count', 'RST Flag Cnt': 'RST Flag Count',
        'SYN Flag Cnt': 'SYN Flag Count', 'Subflow Bwd Byts': 'Subflow Bwd Bytes', 'Subflow Bwd Pkts': 'Subflow Bwd Packets', 'Subflow Fwd Byts': 'Subflow Fwd Bytes',
        'Subflow Fwd Pkts': 'Subflow Fwd Packets', 'Tot Fwd Pkts': 'Total Fwd Packets', 'Tot Bwd Pkts': 'Total Backward Packets', 'TotLen Fwd Pkts': 'Total Length of Fwd Packets',
        'TotLen Bwd Pkts': 'Total Length of Bwd Packets', 'URG Flag Cnt': 'URG Flag Count'
    }
    return df.rename(columns=column_mapping)

def build_feature_matrix(df, scaler):
    expected = scaler.feature_names_in_.tolist()
    cols_to_drop = ['Flow ID','Source IP','Source Port','Destination IP','Destination Port','Protocol','Timestamp','Label']
    X = df.drop(columns=[c for c in cols_to_drop if c in df.columns], errors='ignore')
    for f in expected:
        if f not in X.columns:
            X[f] = 0
    X = X[expected].replace([np.inf,-np.inf],0).fillna(0)
    return scaler.transform(X)

def sequence_label_vector(y_rows, timesteps):
    num_seq = len(y_rows)//timesteps
    trimmed = y_rows[:num_seq*timesteps].reshape(num_seq, timesteps)
    return (trimmed.sum(axis=1) > 0).astype(int), num_seq

def expand_sequence_predictions(seq_probs, seq_preds, timesteps, total_rows):
    row_probs = np.repeat(seq_probs, timesteps)
    row_preds = np.repeat(seq_preds, timesteps)
    if len(row_preds) < total_rows:
        pad = total_rows - len(row_preds)
        row_preds = np.concatenate([row_preds, np.zeros(pad, dtype=int)])
        row_probs = np.concatenate([row_probs, np.zeros(pad, dtype=float)])
    return row_probs, row_preds

def sweep_thresholds(probs, y_true, thresholds, fp_max):
    benign_total = int(np.sum(y_true == 0))
    results = []
    for t in thresholds:
        y_pred = (probs >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        precision = tp / (tp + fp) if tp + fp > 0 else 0
        recall = tp / (tp + fn) if tp + fn > 0 else 0
        f1 = 2*precision*recall/(precision+recall) if precision+recall>0 else 0
        beta = 2
        f2 = (1+beta**2)*precision*recall/(beta**2*precision+recall+1e-9) if precision+recall>0 else 0
        fp_rate = fp/benign_total if benign_total else 0
        results.append({'threshold': float(round(t,4)), 'precision': precision, 'recall': recall, 'f1_score': f1,
                        'f2_score': f2, 'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn, 'fp_rate': fp_rate,
                        'attacks_detected': int(np.sum(y_pred))})
        print(f"Threshold {t:.3f} | Detect {results[-1]['attacks_detected']:,} | P={precision:.3f} R={recall:.3f} F1={f1:.3f} F2={f2:.3f} FP Rate={fp_rate:.5f}")
    feasible = [r for r in results if r['fp_rate'] <= fp_max]
    best = max(feasible, key=lambda r: r['f2_score']) if feasible else max(results, key=lambda r: r['f2_score'])
    return results, best

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-file', default='02-14-2018.csv', help='Labeled CSV file.')
    parser.add_argument('-model', choices=['xgboost','lstm'], default='xgboost', help='Model to calibrate.')
    parser.add_argument('-fp_max', type=float, default=0.01, help='Max allowed false positive rate (FP/(FP+TN)).')
    parser.add_argument('-step', type=float, default=0.05, help='Threshold sweep step size.')
    parser.add_argument('--write_optimal', action='store_true', help='Also write threshold to models/optimal_threshold.txt for app backward compatibility.')
    args = parser.parse_args()

    print("="*60)
    print(f"Threshold Calibration - {args.model.upper()}")
    print("="*60)

    df = load_and_prepare_dataframe(args.file)
    print(f"Dataset shape: {df.shape}")
    print("Label distribution:\n", df['Label'].value_counts())
    df = apply_column_mapping(df)
    y_rows = (df['Label'].str.upper() != 'BENIGN').astype(int).values

    scaler = joblib.load('models/scaler.pkl')
    X_scaled = build_feature_matrix(df, scaler)

    if args.model == 'xgboost':
        model = joblib.load('models/xgboost_model.pkl')
        probs = model.predict_proba(X_scaled)[:,1]
        y_true = y_rows
    else:
        if tf is None:
            raise ImportError('TensorFlow not available for LSTM calibration.')
        model = tf.keras.models.load_model('models/lstm_model.h5')
        timesteps = joblib.load('models/lstm_timesteps.pkl')
        num_seq = len(X_scaled)//timesteps
        trimmed = num_seq*timesteps
        X_seq = X_scaled[:trimmed].reshape(num_seq, timesteps, X_scaled.shape[1])
        seq_probs = model.predict(X_seq, verbose=0).flatten()
        seq_preds = (seq_probs >= 0.5).astype(int)
        row_probs, _ = expand_sequence_predictions(seq_probs, seq_preds, timesteps, len(X_scaled))
        probs = row_probs
        # Sequence labels aggregated first then expanded to rows for consistent metric calculation
        seq_labels, _ = sequence_label_vector(y_rows, timesteps)
        y_true_expanded, _ = expand_sequence_predictions(seq_labels, seq_labels, timesteps, len(X_scaled))
        y_true = y_true_expanded.astype(int)

    print("\nSweeping thresholds...")
    thresholds = np.arange(args.step, 0.991, args.step)
    all_results, best = sweep_thresholds(probs, y_true, thresholds, args.fp_max)

    print("\n"+"="*60)
    print("RECOMMENDED THRESHOLD")
    print("="*60)
    print(f"Best threshold: {best['threshold']:.3f}")
    print(f"Attacks detected: {best['attacks_detected']:,} ({best['attacks_detected']/len(y_true)*100:.2f}%)")
    print(f"Precision: {best['precision']:.4f}  Recall: {best['recall']:.4f}  F1: {best['f1_score']:.4f}  F2: {best['f2_score']:.4f}")
    print(f"FP Rate (FP/Benign): {best['fp_rate']:.6f}")
    print(f"TP: {best['tp']:,}  FP: {best['fp']:,}  TN: {best['tn']:,}  FN: {best['fn']:,}")

    os.makedirs('models', exist_ok=True)
    if args.model == 'xgboost':
        joblib.dump(best['threshold'], 'models/xgboost_threshold.pkl')
        print(f"Saved XGBoost threshold to models/xgboost_threshold.pkl")
    else:
        joblib.dump(best['threshold'], 'models/lstm_threshold.pkl')
        print(f"Saved LSTM threshold to models/lstm_threshold.pkl")
    if args.write_optimal:
        with open('models/optimal_threshold.txt','w') as f:
            f.write(str(best['threshold']))
        print("Mirrored threshold to models/optimal_threshold.txt")

    # Visualization
    print("\nGenerating threshold comparison chart...")
    fig, axes = plt.subplots(2,2, figsize=(14,10))
    ths = [r['threshold'] for r in all_results]
    ax = axes[0,0]
    ax.plot(ths, [r['precision'] for r in all_results], 's-', label='Precision')
    ax.plot(ths, [r['recall'] for r in all_results], '^-', label='Recall')
    ax.plot(ths, [r['f1_score'] for r in all_results], 'd-', label='F1')
    ax.plot(ths, [r['f2_score'] for r in all_results], 'o-', label='F2')
    ax.axvline(best['threshold'], color='red', linestyle='--', label=f'Best {best['threshold']:.3f}')
    ax.set_xlabel('Threshold'); ax.set_ylabel('Score'); ax.set_title('Metrics vs Threshold'); ax.legend(); ax.grid(alpha=0.3)

    ax = axes[0,1]
    ax.plot(ths, [r['attacks_detected'] for r in all_results], 'o-', color='darkblue')
    ax.axvline(best['threshold'], color='red', linestyle='--')
    ax.set_xlabel('Threshold'); ax.set_ylabel('Detections'); ax.set_title('Detections vs Threshold'); ax.grid(alpha=0.3)

    ax = axes[1,0]
    precision_curve, recall_curve, pr_ths = precision_recall_curve(y_true, probs)
    ax.plot(recall_curve, precision_curve, color='purple')
    ax.set_xlabel('Recall'); ax.set_ylabel('Precision'); ax.set_title('Precision-Recall Curve'); ax.grid(alpha=0.3)

    ax = axes[1,1]
    cm = np.array([[best['tn'], best['fp']],[best['fn'], best['tp']]])
    img = ax.imshow(cm, cmap='Blues')
    ax.set_xticks([0,1]); ax.set_yticks([0,1]); ax.set_xticklabels(['Benign','Attack']); ax.set_yticklabels(['Benign','Attack'])
    ax.set_xlabel('Predicted'); ax.set_ylabel('Actual'); ax.set_title(f'Confusion Matrix (t={best['threshold']:.3f})')
    for i in range(2):
        for j in range(2):
            ax.text(j,i,f'{cm[i,j]:,}', ha='center', va='center', color='white' if cm[i,j]>cm.max()/2 else 'black', fontsize=13, fontweight='bold')
    plt.tight_layout(); plt.savefig('threshold_analysis.png', dpi=150, bbox_inches='tight')
    print('✓ Chart saved to threshold_analysis.png')

    print('\n'+'='*60)
    print('Calibration complete.')
    print('='*60)

if __name__ == '__main__':
    main()
