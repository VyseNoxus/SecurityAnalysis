"""
Feature Engineering for Intrusion Detection
Prepares features and labels for XGBoost, LSTM, and One-Class SVM models
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib
import os

def load_data(train_path, test_seen_path, test_unseen_path):
    print("Loading datasets...")
    train_df = pd.read_csv(train_path)
    test_seen_df = pd.read_csv(test_seen_path)
    test_unseen_df = pd.read_csv(test_unseen_path)
    
    print(f"Training: {len(train_df):,} samples")
    print(f"Test Seen: {len(test_seen_df):,} samples")
    print(f"Test Unseen: {len(test_unseen_df):,} samples")
    
    return train_df, test_seen_df, test_unseen_df

def prepare_labels(train_df, test_seen_df, test_unseen_df):
    print("\nPreparing binary labels (BENIGN=0, ATTACK=1)...")
    
    train_df['Binary_Label'] = (train_df['Label'] != 'BENIGN').astype(int)
    test_seen_df['Binary_Label'] = (test_seen_df['Label'] != 'BENIGN').astype(int)
    test_unseen_df['Binary_Label'] = (test_unseen_df['Label'] != 'BENIGN').astype(int)
    
    print(f"Training - Benign: {(train_df['Binary_Label'] == 0).sum():,}, Attack: {(train_df['Binary_Label'] == 1).sum():,}")
    print(f"Test Seen - Benign: {(test_seen_df['Binary_Label'] == 0).sum():,}, Attack: {(test_seen_df['Binary_Label'] == 1).sum():,}")
    print(f"Test Unseen - Benign: {(test_unseen_df['Binary_Label'] == 0).sum():,}, Attack: {(test_unseen_df['Binary_Label'] == 1).sum():,}")
    
    return train_df, test_seen_df, test_unseen_df

def remove_irrelevant_features(df):
    cols_to_drop = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 
                    'Destination Port', 'Protocol', 'Timestamp', 'Label', 'Binary_Label']
    cols_to_drop = [col for col in cols_to_drop if col in df.columns]
    
    features = df.drop(columns=cols_to_drop)
    labels = df['Binary_Label']
    
    return features, labels

def scale_features(X_train, X_test_seen, X_test_unseen, scaler_path='models/scaler.pkl'):
    print("\nScaling features with StandardScaler...")
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_seen_scaled = scaler.transform(X_test_seen)
    X_test_unseen_scaled = scaler.transform(X_test_unseen)
    
    os.makedirs(os.path.dirname(scaler_path), exist_ok=True)
    joblib.dump(scaler, scaler_path)
    print(f"✓ Scaler saved to {scaler_path}")
    
    return X_train_scaled, X_test_seen_scaled, X_test_unseen_scaled

def prepare_data_for_models():
    print("=" * 60)
    print("Feature Engineering")
    print("=" * 60)
    
    train_df, test_seen_df, test_unseen_df = load_data(
        'data/processed/train.csv',
        'data/processed/test_seen.csv',
        'data/processed/test_unseen.csv'
    )
    
    train_df, test_seen_df, test_unseen_df = prepare_labels(
        train_df, test_seen_df, test_unseen_df
    )
    
    print("\nExtracting features...")
    X_train, y_train = remove_irrelevant_features(train_df)
    X_test_seen, y_test_seen = remove_irrelevant_features(test_seen_df)
    X_test_unseen, y_test_unseen = remove_irrelevant_features(test_unseen_df)
    print(f"Feature count: {X_train.shape[1]}")
    
    print("\nHandling infinite values...")
    X_train.replace([np.inf, -np.inf], 0, inplace=True)
    X_test_seen.replace([np.inf, -np.inf], 0, inplace=True)
    X_test_unseen.replace([np.inf, -np.inf], 0, inplace=True)
    
    X_train_scaled, X_test_seen_scaled, X_test_unseen_scaled = scale_features(
        X_train, X_test_seen, X_test_unseen
    )
    
    print("\n" + "=" * 60)
    print("Feature engineering complete!")
    print("=" * 60)
    
    return {
        'X_train': X_train_scaled,
        'y_train': y_train.values,
        'X_test_seen': X_test_seen_scaled,
        'y_test_seen': y_test_seen.values,
        'X_test_unseen': X_test_unseen_scaled,
        'y_test_unseen': y_test_unseen.values,
        'feature_names': X_train.columns.tolist()
    }

if __name__ == '__main__':
    data = prepare_data_for_models()
    print(f"\nData shapes:")
    print(f"X_train: {data['X_train'].shape}")
    print(f"X_test_seen: {data['X_test_seen'].shape}")
    print(f"X_test_unseen: {data['X_test_unseen'].shape}")