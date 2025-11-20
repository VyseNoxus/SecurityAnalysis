"""
Flask Web Application for Model Comparison Dashboard
Displays results from XGBoost, One-Class SVM, and LSTM models
"""

from flask import Flask, render_template, jsonify, request
import json
import os
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from tensorflow import keras

app = Flask(__name__)

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

def load_model_results():
    results = {
        'xgboost': None,
        'ocsvm': None,
        'lstm': None
    }
    
    for model_name in results.keys():
        result_file = RESULTS_DIR / f"{model_name}_results.json"
        if result_file.exists():
            with open(result_file, 'r') as f:
                results[model_name] = json.load(f)
    
    return results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detection')
def detection():
    return render_template('detection.html')

@app.route('/api/results')
def get_results():
    results = load_model_results()
    return jsonify(results)

@app.route('/api/comparison')
def get_comparison():
    results = load_model_results()
    
    comparison = {
        'models': [],
        'metrics': {
            'train_accuracy': [],
            'test_seen_accuracy': [],
            'test_unseen_accuracy': [],
            'train_f1': [],
            'test_seen_f1': [],
            'test_unseen_f1': [],
            'train_precision': [],
            'test_seen_precision': [],
            'test_unseen_precision': [],
            'train_recall': [],
            'test_seen_recall': [],
            'test_unseen_recall': []
        }
    }
    
    for model_name, model_data in results.items():
        if model_data:
            comparison['models'].append(model_name.upper())
            
            for dataset in ['train', 'test_seen', 'test_unseen']:
                if dataset in model_data:
                    comparison['metrics'][f'{dataset}_accuracy'].append(
                        model_data[dataset].get('accuracy', 0) * 100
                    )
                    comparison['metrics'][f'{dataset}_f1'].append(
                        model_data[dataset].get('f1_score', 0) * 100
                    )
                    comparison['metrics'][f'{dataset}_precision'].append(
                        model_data[dataset].get('precision', 0) * 100
                    )
                    comparison['metrics'][f'{dataset}_recall'].append(
                        model_data[dataset].get('recall', 0) * 100
                    )
    
    return jsonify(comparison)

@app.route('/api/detect', methods=['POST'])
def detect_attacks():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        model_name = request.form.get('model', 'xgboost')
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        df = pd.read_csv(file)
        df.columns = df.columns.str.strip()
        
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
        
        scaler = joblib.load('models/scaler.pkl')
        expected_features = scaler.feature_names_in_.tolist()
        
        cols_to_drop = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 
                        'Destination Port', 'Protocol', 'Timestamp', 'Label']
        cols_to_drop = [col for col in cols_to_drop if col in df.columns]
        
        source_ips = df['Source IP'].tolist() if 'Source IP' in df.columns else [None] * len(df)
        dest_ips = df['Destination IP'].tolist() if 'Destination IP' in df.columns else [None] * len(df)
        flow_durations = df['Flow Duration'].tolist() if 'Flow Duration' in df.columns else [None] * len(df)
        true_labels = df['Label'].tolist() if 'Label' in df.columns else [None] * len(df)
        
        X = df.drop(columns=cols_to_drop, errors='ignore')
        
        for feature in expected_features:
            if feature not in X.columns:
                X[feature] = 0
        
        X = X[expected_features]
        X.replace([np.inf, -np.inf], 0, inplace=True)
        X.fillna(0, inplace=True)
        
        X_scaled = scaler.transform(X)
        
        # Determine model-specific threshold with graceful fallback order:
        # 1. Model-specific threshold file (xgboost_threshold.pkl / lstm_threshold.pkl)
        # 2. Legacy optimal_threshold.txt
        # 3. Default 0.1
        def load_threshold(name):
            specific_path = f'models/{name}_threshold.pkl'
            legacy_path = 'models/optimal_threshold.txt'
            if os.path.exists(specific_path):
                try:
                    return float(joblib.load(specific_path))
                except Exception:
                    pass
            if os.path.exists(legacy_path):
                try:
                    with open(legacy_path, 'r') as f:
                        return float(f.read().strip())
                except Exception:
                    pass
            return 0.1

        if model_name == 'xgboost':
            threshold = load_threshold('xgboost')
            model = joblib.load('models/xgboost_model.pkl')
            probabilities_raw = model.predict_proba(X_scaled)[:, 1]
            predictions = (probabilities_raw >= threshold).astype(int)
            probabilities = np.where(predictions == 1, probabilities_raw, 1 - probabilities_raw)
        elif model_name == 'ocsvm':
            model = joblib.load('models/ocsvm_model.pkl')
            raw_predictions = model.predict(X_scaled)
            predictions = np.where(raw_predictions == 1, 0, 1)
            probabilities = np.where(predictions == 1, 0.9, 0.1)
        elif model_name == 'lstm':
            threshold = load_threshold('lstm')
            model = keras.models.load_model('models/lstm_model.h5')
            timesteps = joblib.load('models/lstm_timesteps.pkl')
            
            num_sequences = len(X_scaled) // timesteps
            trimmed_samples = num_sequences * timesteps
            X_lstm = X_scaled[:trimmed_samples].reshape(num_sequences, timesteps, X_scaled.shape[1])
            
            # Sequence-level probabilities/predictions
            sequence_probs = model.predict(X_lstm, verbose=0).flatten()
            sequence_preds = (sequence_probs >= threshold).astype(int)
            
            # Expand each sequence prediction/probability across its timesteps to map back to per-row granularity
            predictions = np.repeat(sequence_preds, timesteps)
            probabilities = np.repeat(sequence_probs, timesteps)
            
            # Pad any leftover (incomplete final sequence) rows with benign prediction and zero confidence
            if len(predictions) < len(X_scaled):
                remainder = len(X_scaled) - len(predictions)
                predictions = np.concatenate([predictions, np.zeros(remainder, dtype=int)])
                probabilities = np.concatenate([probabilities, np.zeros(remainder, dtype=float)])
        
        total_samples = len(predictions)
        attacks_detected = int(np.sum(predictions))
        benign_traffic = total_samples - attacks_detected
        
        attack_types = {}
        if true_labels[0] is not None:
            for i, (label, pred) in enumerate(zip(true_labels, predictions)):
                if pred == 1 and label and label.upper() != 'BENIGN':
                    attack_types[label] = attack_types.get(label, 0) + 1
        
        detections = []
        for i in range(min(100, total_samples)):
            detections.append({
                'prediction': 'ATTACK' if predictions[i] == 1 else 'BENIGN',
                'confidence': round(float(probabilities[i]) * 100, 2),
                'source_ip': str(source_ips[i]) if i < len(source_ips) and source_ips[i] else 'N/A',
                'dest_ip': str(dest_ips[i]) if i < len(dest_ips) and dest_ips[i] else 'N/A',
                'flow_duration': str(flow_durations[i]) if i < len(flow_durations) and flow_durations[i] else 'N/A',
                'actual_label': str(true_labels[i]) if i < len(true_labels) and true_labels[i] else 'Unknown'
            })
        
        batch_size = 1000
        timeline = []
        timeline_labels = []
        for i in range(0, total_samples, batch_size):
            batch_attacks = np.sum(predictions[i:i+batch_size])
            timeline.append(int(batch_attacks))
            timeline_labels.append(f"{i}-{min(i+batch_size, total_samples)}")
        
        if len(timeline) > 5:
            smoothed_timeline = []
            for i in range(len(timeline)):
                if i == 0:
                    smoothed_timeline.append(int((timeline[i] + timeline[i+1]) / 2))
                elif i == len(timeline) - 1:
                    smoothed_timeline.append(int((timeline[i-1] + timeline[i]) / 2))
                else:
                    smoothed_timeline.append(int((timeline[i-1] + timeline[i] + timeline[i+1]) / 3))
            timeline = smoothed_timeline
        
        avg_confidence = round(float(np.mean(probabilities)) * 100, 2)
        
        confidence_ranges = {
            '0-20%': 0, '20-40%': 0, '40-60%': 0, '60-80%': 0, '80-100%': 0
        }
        for prob in probabilities:
            conf_pct = prob * 100
            if conf_pct < 20:
                confidence_ranges['0-20%'] += 1
            elif conf_pct < 40:
                confidence_ranges['20-40%'] += 1
            elif conf_pct < 60:
                confidence_ranges['40-60%'] += 1
            elif conf_pct < 80:
                confidence_ranges['60-80%'] += 1
            else:
                confidence_ranges['80-100%'] += 1
        
        return jsonify({
            'total_samples': total_samples,
            'attacks_detected': attacks_detected,
            'benign_traffic': benign_traffic,
            'attack_rate': round((attacks_detected / total_samples) * 100, 2),
            'predictions': detections,
            'timeline': timeline,
            'timeline_labels': timeline_labels,
            'attack_types': attack_types,
            'confidence_distribution': confidence_ranges,
            'avg_confidence': avg_confidence
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("=" * 60)
    print("Model Comparison Dashboard")
    print("=" * 60)
    print("\nStarting Flask server...")
    print("Dashboard: http://localhost:5000")
    print("\nPress CTRL+C to stop")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
