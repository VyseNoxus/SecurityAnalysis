"""
LSTM Model Training and Evaluation
Sequential pattern detection using deep learning
"""

import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
import joblib
import time
import json
import os
from feature_engineering import prepare_data_for_models

def reshape_for_lstm(X, timesteps=10):
    samples = X.shape[0]
    features = X.shape[1]
    
    num_complete_sequences = samples // timesteps
    trimmed_samples = num_complete_sequences * timesteps
    
    X_trimmed = X[:trimmed_samples]
    X_reshaped = X_trimmed.reshape(num_complete_sequences, timesteps, features)
    
    return X_reshaped, trimmed_samples

def build_lstm_model(input_shape):
    model = keras.Sequential([
        layers.LSTM(64, return_sequences=True, input_shape=input_shape),
        layers.Dropout(0.2),
        layers.LSTM(32, return_sequences=False),
        layers.Dropout(0.2),
        layers.Dense(16, activation='relu'),
        layers.Dropout(0.2),
        layers.Dense(1, activation='sigmoid')
    ])
    
    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy', tf.keras.metrics.Precision(), tf.keras.metrics.Recall()]
    )
    
    return model

def train_lstm(X_train, y_train, timesteps=10, epochs=20, batch_size=128):
    print("\n" + "=" * 60)
    print("Training LSTM Model")
    print("=" * 60)
    
    print(f"\nReshaping data (timesteps={timesteps})...")
    X_train_lstm, trimmed_samples = reshape_for_lstm(X_train, timesteps)
    y_train_lstm = y_train[:trimmed_samples].reshape(-1, timesteps)[:, 0]
    
    print(f"Original samples: {len(y_train):,}")
    print(f"LSTM sequences: {len(y_train_lstm):,}")
    print(f"Input shape: {X_train_lstm.shape}")
    
    print("\nBuilding architecture...")
    model = build_lstm_model(input_shape=(timesteps, X_train.shape[1]))
    
    print("\nModel Architecture:")
    model.summary()
    
    print(f"\nTraining (epochs={epochs}, batch_size={batch_size})...")
    start_time = time.time()
    
    history = model.fit(
        X_train_lstm, y_train_lstm,
        epochs=epochs,
        batch_size=batch_size,
        validation_split=0.2,
        verbose=1
    )
    
    training_time = time.time() - start_time
    print(f"\n✓ Training completed in {training_time:.2f}s")
    
    return model, training_time, timesteps

def evaluate_model(model, X_test, y_test, timesteps, dataset_name):
    print(f"\n{dataset_name} Evaluation:")
    print("-" * 60)
    
    X_test_lstm, trimmed_samples = reshape_for_lstm(X_test, timesteps)
    y_test_lstm = y_test[:trimmed_samples].reshape(-1, timesteps)[:, 0]
    
    start_time = time.time()
    y_pred_proba = model.predict(X_test_lstm, verbose=0)
    y_pred = (y_pred_proba > 0.5).astype(int).flatten()
    prediction_time = time.time() - start_time
    
    accuracy = accuracy_score(y_test_lstm, y_pred)
    precision = precision_score(y_test_lstm, y_pred, zero_division=0)
    recall = recall_score(y_test_lstm, y_pred, zero_division=0)
    f1 = f1_score(y_test_lstm, y_pred, zero_division=0)
    
    print(f"Samples: {len(y_test_lstm):,}")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"Prediction time: {prediction_time:.4f}s")
    
    cm = confusion_matrix(y_test_lstm, y_pred)
    print(f"\nConfusion Matrix:")
    print(f"  TN: {cm[0,0]:>6,}  FP: {cm[0,1]:>6,}")
    print(f"  FN: {cm[1,0]:>6,}  TP: {cm[1,1]:>6,}")
    
    print(f"\nClassification Report:")
    print(classification_report(y_test_lstm, y_pred, target_names=['BENIGN', 'ATTACK'], zero_division=0))
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'confusion_matrix': cm,
        'prediction_time': prediction_time
    }

def main():
    print("=" * 60)
    print("LSTM Training")
    print("=" * 60)
    
    data = prepare_data_for_models()
    
    model, training_time, timesteps = train_lstm(
        data['X_train'], 
        data['y_train'],
        timesteps=10,
        epochs=20,
        batch_size=128
    )
    
    model_path = 'models/lstm_model.h5'
    model.save(model_path)
    print(f"\n✓ Model saved to {model_path}")
    
    joblib.dump(timesteps, 'models/lstm_timesteps.pkl')
    
    print("\n" + "=" * 60)
    print("Model Evaluation")
    print("=" * 60)
    
    train_results = evaluate_model(model, data['X_train'], data['y_train'], timesteps, "Training Set")
    seen_results = evaluate_model(model, data['X_test_seen'], data['y_test_seen'], timesteps, "Test Set (Seen Attacks)")
    unseen_results = evaluate_model(model, data['X_test_unseen'], data['y_test_unseen'], timesteps, "Test Set (Unseen Attacks)")
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Training time: {training_time:.2f}s")
    print(f"\nAccuracy:")
    print(f"  Training:    {train_results['accuracy']:.4f}")
    print(f"  Test Seen:   {seen_results['accuracy']:.4f}")
    print(f"  Test Unseen: {unseen_results['accuracy']:.4f}")
    print(f"\nF1-Score:")
    print(f"  Training:    {train_results['f1_score']:.4f}")
    print(f"  Test Seen:   {seen_results['f1_score']:.4f}")
    print(f"  Test Unseen: {unseen_results['f1_score']:.4f}")
    print(f"\nGeneralization Gap:")
    print(f"  Accuracy:  {abs(seen_results['accuracy'] - unseen_results['accuracy']):.4f}")
    print(f"  F1-Score:  {abs(seen_results['f1_score'] - unseen_results['f1_score']):.4f}")
    
    results_data = {
        'model_name': 'LSTM',
        'training_time': training_time,
        'train': {
            'accuracy': float(train_results['accuracy']),
            'precision': float(train_results['precision']),
            'recall': float(train_results['recall']),
            'f1_score': float(train_results['f1_score']),
            'confusion_matrix': train_results['confusion_matrix'].tolist()
        },
        'test_seen': {
            'accuracy': float(seen_results['accuracy']),
            'precision': float(seen_results['precision']),
            'recall': float(seen_results['recall']),
            'f1_score': float(seen_results['f1_score']),
            'confusion_matrix': seen_results['confusion_matrix'].tolist()
        },
        'test_unseen': {
            'accuracy': float(unseen_results['accuracy']),
            'precision': float(unseen_results['precision']),
            'recall': float(unseen_results['recall']),
            'f1_score': float(unseen_results['f1_score']),
            'confusion_matrix': unseen_results['confusion_matrix'].tolist()
        }
    }
    
    os.makedirs('results', exist_ok=True)
    results_path = 'results/lstm_results.json'
    with open(results_path, 'w') as f:
        json.dump(results_data, f, indent=2)
    print(f"\n✓ Results saved to {results_path}")
    
    return {
        'model': model,
        'training_time': training_time,
        'train_results': train_results,
        'seen_results': seen_results,
        'unseen_results': unseen_results
    }

if __name__ == '__main__':
    results = main()
