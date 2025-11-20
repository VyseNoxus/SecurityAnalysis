"""
LSTM Model Training and Evaluation
Sequential pattern detection using deep learning
"""

import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score, precision_recall_curve
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
import joblib
import time
import json
import os
from feature_engineering import prepare_data_for_models

def reshape_for_lstm(X, timesteps=10):
    """Reshapes 2D array into 3D array for LSTM [samples, timesteps, features]."""
    num_sequences = len(X) // timesteps
    trimmed_len = num_sequences * timesteps
    X_trimmed = X[:trimmed_len]
    return X_trimmed.reshape(num_sequences, timesteps, X.shape[1])

def _label_sequences(y, timesteps=10, mode='any'):
    """
    Aggregates point-wise labels into sequence labels.
    Mode 'any': a sequence is an attack if ANY timestep within it is an attack.
    """
    num_sequences = len(y) // timesteps
    trimmed_len = num_sequences * timesteps
    y_trimmed = y[:trimmed_len].reshape(num_sequences, timesteps)
    
    if mode == 'any':
        y_sequences = (np.sum(y_trimmed, axis=1) > 0).astype(int)
    else:
        y_sequences = (np.sum(y_trimmed, axis=1) > 0).astype(int)
        
    return y_sequences

def _find_best_threshold(y_true, y_scores):
    """Find the optimal probability threshold to maximize F1-score."""
    precision, recall, thresholds = precision_recall_curve(y_true, y_scores)
    f1 = (2 * precision[:-1] * recall[:-1]) / (precision[:-1] + recall[:-1] + 1e-8)
    if len(f1) == 0: return 0.5
    idx = np.argmax(f1)
    return float(thresholds[idx])

def build_lstm_model(input_shape):
    model = keras.Sequential([
        layers.LSTM(64, return_sequences=True, input_shape=input_shape),
        layers.Dropout(0.2),
        layers.LSTM(32),
        layers.Dropout(0.2),
        layers.Dense(16, activation='relu'),
        layers.Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy', tf.keras.metrics.Precision(name='precision'), tf.keras.metrics.Recall(name='recall')])
    return model

def train_lstm(X_train, y_train, timesteps=10, epochs=25, batch_size=128):
    print("\n" + "=" * 60); print("Training LSTM Model"); print("=" * 60)
    
    print(f"\nReshaping data and labeling sequences (timesteps={timesteps})...")
    X_train_lstm = reshape_for_lstm(X_train, timesteps)
    y_train_lstm = _label_sequences(y_train, timesteps)
    print(f"Input shape: {X_train_lstm.shape}, Label shape: {y_train_lstm.shape}")

    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train_lstm, y_train_lstm, test_size=0.2, random_state=42, stratify=y_train_lstm
    )
    
    model = build_lstm_model(input_shape=(timesteps, X_train.shape[1]))
    model.summary()
    
    # Handle class imbalance with class weights
    class_weights = compute_class_weight('balanced', classes=np.unique(y_tr), y=y_tr)
    class_weights_dict = dict(enumerate(class_weights))
    print(f"\nClass weights: {class_weights_dict}")
    
    callbacks = [
        keras.callbacks.EarlyStopping(monitor='val_recall', mode='max', patience=5, restore_best_weights=True, verbose=1),
        keras.callbacks.ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=3, verbose=1)
    ]
    
    print(f"\nTraining (epochs={epochs}, batch_size={batch_size})...")
    start_time = time.time()
    model.fit(X_tr, y_tr, epochs=epochs, batch_size=batch_size, validation_data=(X_val, y_val),
              callbacks=callbacks, class_weight=class_weights_dict, verbose=1)
    training_time = time.time() - start_time
    print(f"\n✓ Training completed in {training_time:.2f}s")
    
    print("\nTuning probability threshold on validation set...")
    y_val_scores = model.predict(X_val, verbose=0).ravel()
    best_threshold = _find_best_threshold(y_val, y_val_scores)
    print(f"Chosen threshold: {best_threshold:.4f}")
    
    return model, training_time, timesteps, best_threshold

def evaluate_model(model, X_test, y_test, timesteps, dataset_name, threshold=0.5):
    print(f"\n{dataset_name} Evaluation:"); print("-" * 60)
    
    X_test_lstm = reshape_for_lstm(X_test, timesteps)
    y_test_lstm = _label_sequences(y_test, timesteps)
    
    start_time = time.time()
    y_scores = model.predict(X_test_lstm, verbose=0).flatten()
    y_pred = (y_scores >= threshold).astype(int)
    prediction_time = time.time() - start_time
    
    accuracy = accuracy_score(y_test_lstm, y_pred)
    precision = precision_score(y_test_lstm, y_pred, zero_division=0)
    recall = recall_score(y_test_lstm, y_pred, zero_division=0)
    f1 = f1_score(y_test_lstm, y_pred, zero_division=0)
    
    print(f"Accuracy:  {accuracy:.4f}\nPrecision: {precision:.4f}\nRecall:    {recall:.4f}\nF1-Score:  {f1:.4f}")
    print(f"Prediction time: {prediction_time:.4f}s")
    
    cm = confusion_matrix(y_test_lstm, y_pred, labels=[0, 1])
    print(f"\nConfusion Matrix:\n  TN: {cm[0,0]:>6,}  FP: {cm[0,1]:>6,}\n  FN: {cm[1,0]:>6,}  TP: {cm[1,1]:>6,}")
    print(f"\nClassification Report:\n{classification_report(y_test_lstm, y_pred, labels=[0, 1], target_names=['BENIGN', 'ATTACK'], zero_division=0)}")
    
    return {
        'accuracy': accuracy, 'precision': precision, 'recall': recall, 'f1_score': f1,
        'confusion_matrix': cm, 'prediction_time': prediction_time
    }

def main():
    print("=" * 60); print("LSTM Training"); print("=" * 60)
    data = prepare_data_for_models()
    
    model, training_time, timesteps, best_threshold = train_lstm(data['X_train'], data['y_train'])
    
    os.makedirs('models', exist_ok=True)
    model.save('models/lstm_model.h5')
    joblib.dump(timesteps, 'models/lstm_timesteps.pkl')
    joblib.dump(best_threshold, 'models/lstm_threshold.pkl')
    print(f"\n✓ Model, timesteps, and threshold saved.")
    
    print("\n" + "=" * 60); print("Model Evaluation"); print("=" * 60)
    
    train_results = evaluate_model(model, data['X_train'], data['y_train'], timesteps, "Training Set", threshold=best_threshold)
    seen_results = evaluate_model(model, data['X_test_seen'], data['y_test_seen'], timesteps, "Test Set (Seen Attacks)", threshold=best_threshold)
    unseen_results = evaluate_model(model, data['X_test_unseen'], data['y_test_unseen'], timesteps, "Test Set (Unseen Attacks)", threshold=best_threshold)
    
    print("\n" + "=" * 60); print("SUMMARY"); print("=" * 60)
    print(f"Training time: {training_time:.2f}s")
    print(f"Optimal Threshold: {best_threshold:.4f}")
    print(f"\nAccuracy:\n  Training:    {train_results['accuracy']:.4f}\n  Test Seen:   {seen_results['accuracy']:.4f}\n  Test Unseen: {unseen_results['accuracy']:.4f}")
    print(f"\nF1-Score:\n  Training:    {train_results['f1_score']:.4f}\n  Test Seen:   {seen_results['f1_score']:.4f}\n  Test Unseen: {unseen_results['f1_score']:.4f}")

    results_data = {
        'model_name': 'LSTM', 'training_time': training_time, 'threshold': float(best_threshold),
        'train': {k: v.tolist() if isinstance(v, np.ndarray) else float(v) for k, v in train_results.items()},
        'test_seen': {k: v.tolist() if isinstance(v, np.ndarray) else float(v) for k, v in seen_results.items()},
        'test_unseen': {k: v.tolist() if isinstance(v, np.ndarray) else float(v) for k, v in unseen_results.items()}
    }
    
    os.makedirs('results', exist_ok=True)
    with open('results/lstm_results.json', 'w') as f:
        json.dump(results_data, f, indent=2)
    print(f"\n✓ Results saved to results/lstm_results.json")

if __name__ == '__main__':
    main()