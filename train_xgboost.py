"""
XGBoost Model Training and Evaluation
Gradient Boosting for intrusion detection
"""

import numpy as np
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score, precision_recall_curve
from sklearn.model_selection import train_test_split
import joblib
import time
import json
import os
from feature_engineering import prepare_data_for_models

def _find_best_threshold(y_true, y_scores):
    """Find the optimal probability threshold to maximize F1-score."""
    precision, recall, thresholds = precision_recall_curve(y_true, y_scores)
    # Add a small epsilon to avoid division by zero
    f1 = (2 * precision[:-1] * recall[:-1]) / (precision[:-1] + recall[:-1] + 1e-8)
    
    if len(f1) == 0:
        return 0.5 # Default if no thresholds are found

    idx = int(np.argmax(f1))
    return float(thresholds[idx])

def train_xgboost(X_train, y_train):
    print("\n" + "=" * 60)
    print("Training XGBoost Model")
    print("=" * 60)
    
    # Handle class imbalance via scale_pos_weight (highly recommended for IDS)
    pos = int(np.sum(y_train == 1))
    neg = int(np.sum(y_train == 0))
    scale_pos_weight = (neg / max(pos, 1)) if pos > 0 else 1.0
    
    params = {
        'objective': 'binary:logistic',
        'max_depth': 6,
        'learning_rate': 0.05,
        'n_estimators': 1000, # Increased for better performance with early stopping
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'random_state': 42,
        'eval_metric': 'logloss',
        'tree_method': 'hist', # Faster training
        'scale_pos_weight': scale_pos_weight
    }
    
    print("\nModel parameters:")
    for key, value in params.items():
        print(f"  {key}: {value}")
    
    print("\nTraining...")
    start_time = time.time()
    
    # Create a validation set for early stopping and threshold tuning
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
    )
    
    model = xgb.XGBClassifier(**params)
    model.fit(
        X_tr, y_tr,
        eval_set=[(X_val, y_val)],
        early_stopping_rounds=50, # Stop if validation loss doesn't improve for 50 rounds
        verbose=False
    )
    
    training_time = time.time() - start_time
    print(f"✓ Training completed in {training_time:.2f} seconds")
    
    # Tune the decision threshold on the validation set to maximize F1
    print("\nTuning probability threshold on validation set...")
    y_val_scores = model.predict_proba(X_val)[:, 1]
    best_threshold = _find_best_threshold(y_val, y_val_scores)
    print(f"Chosen threshold: {best_threshold:.4f}")
    
    return model, training_time, best_threshold

def evaluate_model(model, X_test, y_test, dataset_name, threshold=0.5):
    print(f"\n{dataset_name} Evaluation:")
    print("-" * 60)
    
    start_time = time.time()
    # Predict probabilities and apply the optimized threshold
    y_scores = model.predict_proba(X_test)[:, 1]
    y_pred = (y_scores >= threshold).astype(int)
    prediction_time = time.time() - start_time
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"Prediction time: {prediction_time:.4f}s")
    
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    print(f"\nConfusion Matrix:")
    print(f"  TN: {cm[0,0]:>6,}  FP: {cm[0,1]:>6,}")
    print(f"  FN: {cm[1,0]:>6,}  TP: {cm[1,1]:>6,}")
    
    print(f"\nClassification Report:")
    print(classification_report(y_test, y_pred, labels=[0, 1], target_names=['BENIGN', 'ATTACK'], zero_division=0))
    
    return {
        'accuracy': accuracy, 'precision': precision, 'recall': recall, 'f1_score': f1,
        'confusion_matrix': cm, 'prediction_time': prediction_time
    }

def main():
    print("=" * 60); print("XGBoost Training"); print("=" * 60)
    
    data = prepare_data_for_models()
    model, training_time, best_threshold = train_xgboost(data['X_train'], data['y_train'])
    
    os.makedirs('models', exist_ok=True)
    joblib.dump(model, 'models/xgboost_model.pkl')
    joblib.dump(best_threshold, 'models/xgboost_threshold.pkl')
    print(f"\n✓ Model and threshold saved.")
    
    print("\n" + "=" * 60); print("Model Evaluation"); print("=" * 60)
    
    # Evaluate all datasets using the single best threshold
    train_results = evaluate_model(model, data['X_train'], data['y_train'], "Training Set", threshold=best_threshold)
    seen_results = evaluate_model(model, data['X_test_seen'], data['y_test_seen'], "Test Set (Seen Attacks)", threshold=best_threshold)
    unseen_results = evaluate_model(model, data['X_test_unseen'], data['y_test_unseen'], "Test Set (Unseen Attacks)", threshold=best_threshold)
    
    print("\n" + "=" * 60); print("SUMMARY"); print("=" * 60)
    print(f"Training time: {training_time:.2f}s")
    print(f"Optimal Threshold: {best_threshold:.4f}")
    print(f"\nAccuracy:\n  Training:    {train_results['accuracy']:.4f}\n  Test Seen:   {seen_results['accuracy']:.4f}\n  Test Unseen: {unseen_results['accuracy']:.4f}")
    print(f"\nF1-Score:\n  Training:    {train_results['f1_score']:.4f}\n  Test Seen:   {seen_results['f1_score']:.4f}\n  Test Unseen: {unseen_results['f1_score']:.4f}")
    
    results_data = {
        'model_name': 'XGBoost', 'training_time': training_time, 'threshold': float(best_threshold),
        'train': {k: v.tolist() if isinstance(v, np.ndarray) else float(v) for k, v in train_results.items()},
        'test_seen': {k: v.tolist() if isinstance(v, np.ndarray) else float(v) for k, v in seen_results.items()},
        'test_unseen': {k: v.tolist() if isinstance(v, np.ndarray) else float(v) for k, v in unseen_results.items()}
    }
    
    os.makedirs('results', exist_ok=True)
    with open('results/xgboost_results.json', 'w') as f:
        json.dump(results_data, f, indent=2)
    print(f"\n✓ Results saved to results/xgboost_results.json")

if __name__ == '__main__':
    main()