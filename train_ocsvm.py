"""
One-Class SVM Model Training and Evaluation
Anomaly detection - trains only on benign traffic to detect attacks as anomalies
"""

import numpy as np
from sklearn.svm import OneClassSVM
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
import joblib
import time
import json
import os
from feature_engineering import prepare_data_for_models

def _tune_one_class_svm(X_train, y_train):
    """Simple grid search for OCSVM using a validation split to maximize F1."""
    print("\nTuning OCSVM hyperparameters (nu, gamma)...")
    # Use a stratified split to ensure validation set has both classes
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
    )
    # The model is still only trained on benign data from the training split
    X_tr_benign = X_tr[y_tr == 0]
    
    # Use a smaller sample for tuning to speed up grid search
    sample_size = min(20000, len(X_tr_benign))
    print(f"  Using {sample_size:,} samples for hyperparameter tuning...")
    indices = np.random.RandomState(42).choice(len(X_tr_benign), sample_size, replace=False)
    X_tr_benign_sample = X_tr_benign[indices]
    
    search_space = {
        'nu': [0.01, 0.05, 0.1],      # Contamination rate
        'gamma': ['scale', 'auto']  # Kernel coefficient
    }
    best = {'params': None, 'f1': -1}

    for nu in search_space['nu']:
        for gamma in search_space['gamma']:
            print(f"  Trying nu={nu}, gamma={gamma}...")
            model = OneClassSVM(kernel='rbf', gamma=gamma, nu=nu, max_iter=5000, cache_size=1500, tol=1e-3)
            model.fit(X_tr_benign_sample)
            
            # Evaluate on the validation set
            y_pred_raw = model.predict(X_val)
            y_pred = np.where(y_pred_raw == 1, 0, 1) # Convert to 0/1
            f1 = f1_score(y_val, y_pred, zero_division=0)
            
            if f1 > best['f1']:
                best = {'params': {'nu': nu, 'gamma': gamma}, 'f1': f1}

    print(f"✓ Best OCSVM params from search: {best['params']} (Validation F1={best['f1']:.4f})")
    return best['params']

def train_one_class_svm(X_train, y_train):
    print("\n" + "=" * 60); print("Training One-Class SVM Model"); print("=" * 60)
    
    # Train only on BENIGN traffic (anomaly detection approach)
    X_benign = X_train[y_train == 0]
    print(f"\nTraining on all BENIGN traffic: {len(X_benign):,} samples")
    
    # Hyperparameter tuning
    tuned_params = _tune_one_class_svm(X_train, y_train)
    params = {
        'kernel': 'rbf',
        'gamma': tuned_params.get('gamma', 'auto'),
        'nu': tuned_params.get('nu', 0.05),
        'max_iter': 10000,   # Sufficient for convergence
        'cache_size': 2000,  # More memory for faster training (MB)
        'tol': 1e-3,         # Relaxed tolerance for faster convergence
        'shrinking': True,   # Enable shrinking heuristic (default, but explicit)
    }
    
    print("\nFinal Model parameters:")
    for key, value in params.items(): print(f"  {key}: {value}")
    
    print("\nTraining final model...")
    start_time = time.time()
    model = OneClassSVM(**params)
    model.fit(X_benign)
    training_time = time.time() - start_time
    print(f"✓ Training completed in {training_time:.2f} seconds")
    
    return model, training_time

def evaluate_model(model, X_test, y_test, dataset_name):
    print(f"\n{dataset_name} Evaluation:"); print("-" * 60)
    
    start_time = time.time()
    y_pred_raw = model.predict(X_test) # 1 for inlier (benign), -1 for outlier (attack)
    prediction_time = time.time() - start_time
    
    y_pred = np.where(y_pred_raw == 1, 0, 1) # Convert to standard 0/1 labels
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    
    print(f"Accuracy:  {accuracy:.4f}\nPrecision: {precision:.4f}\nRecall:    {recall:.4f}\nF1-Score:  {f1:.4f}")
    print(f"Prediction time: {prediction_time:.4f}s")
    
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    print(f"\nConfusion Matrix:\n  TN: {cm[0,0]:>6,}  FP: {cm[0,1]:>6,}\n  FN: {cm[1,0]:>6,}  TP: {cm[1,1]:>6,}")
    print(f"\nClassification Report:\n{classification_report(y_test, y_pred, labels=[0, 1], target_names=['BENIGN', 'ATTACK'], zero_division=0)}")
    
    return {
        'accuracy': accuracy, 'precision': precision, 'recall': recall, 'f1_score': f1,
        'confusion_matrix': cm, 'prediction_time': prediction_time
    }

def main():
    print("=" * 60); print("One-Class SVM Training"); print("=" * 60)
    
    data = prepare_data_for_models()
    model, training_time = train_one_class_svm(data['X_train'], data['y_train'])
    
    os.makedirs('models', exist_ok=True)
    joblib.dump(model, 'models/ocsvm_model.pkl')
    print(f"\n✓ Model saved to models/ocsvm_model.pkl")
    
    print("\n" + "=" * 60); print("Model Evaluation"); print("=" * 60)
    
    train_results = evaluate_model(model, data['X_train'], data['y_train'], "Training Set")
    seen_results = evaluate_model(model, data['X_test_seen'], data['y_test_seen'], "Test Set (Seen Attacks)")
    unseen_results = evaluate_model(model, data['X_test_unseen'], data['y_test_unseen'], "Test Set (Unseen Attacks)")
    
    print("\n" + "=" * 60); print("SUMMARY"); print("=" * 60)
    print(f"Training time: {training_time:.2f}s")
    print(f"\nAccuracy:\n  Training:    {train_results['accuracy']:.4f}\n  Test Seen:   {seen_results['accuracy']:.4f}\n  Test Unseen: {unseen_results['accuracy']:.4f}")
    print(f"\nF1-Score:\n  Training:    {train_results['f1_score']:.4f}\n  Test Seen:   {seen_results['f1_score']:.4f}\n  Test Unseen: {unseen_results['f1_score']:.4f}")

    results_data = {
        'model_name': 'One-Class SVM', 'training_time': training_time,
        'train': {k: v.tolist() if isinstance(v, np.ndarray) else float(v) for k, v in train_results.items()},
        'test_seen': {k: v.tolist() if isinstance(v, np.ndarray) else float(v) for k, v in seen_results.items()},
        'test_unseen': {k: v.tolist() if isinstance(v, np.ndarray) else float(v) for k, v in unseen_results.items()}
    }
    
    os.makedirs('results', exist_ok=True)
    with open('results/ocsvm_results.json', 'w') as f:
        json.dump(results_data, f, indent=2)
    print(f"\n✓ Results saved to results/ocsvm_results.json")

if __name__ == '__main__':
    main()