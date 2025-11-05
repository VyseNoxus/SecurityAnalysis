"""
One-Class SVM Model Training and Evaluation
Anomaly detection - trains only on benign traffic to detect attacks as anomalies
"""

import numpy as np
from sklearn.svm import OneClassSVM
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
import joblib
import time
import json
import os
from feature_engineering import prepare_data_for_models

def train_one_class_svm(X_train, y_train):
    print("\n" + "=" * 60)
    print("Training One-Class SVM Model")
    print("=" * 60)
    
    # Train only on BENIGN traffic (anomaly detection approach)
    X_benign = X_train[y_train == 0]
    print(f"\nTraining on BENIGN traffic only: {len(X_benign):,} samples")
    
    params = {
        'kernel': 'rbf',
        'gamma': 'auto',
        'nu': 0.05,
        'max_iter': 5000
    }
    
    print("\nModel parameters:")
    for key, value in params.items():
        print(f"  {key}: {value}")
    
    print("\nTraining...")
    start_time = time.time()
    
    model = OneClassSVM(**params)
    model.fit(X_benign)
    
    training_time = time.time() - start_time
    print(f"✓ Training completed in {training_time:.2f} seconds")
    
    return model, training_time

def evaluate_model(model, X_test, y_test, dataset_name):
    print(f"\n{dataset_name} Evaluation:")
    print("-" * 60)
    
    # Predictions: 1 = inlier (BENIGN), -1 = outlier (ATTACK)
    start_time = time.time()
    y_pred_raw = model.predict(X_test)
    prediction_time = time.time() - start_time
    
    # Convert: -1 (outlier) -> 1 (attack), 1 (inlier) -> 0 (benign)
    y_pred = np.where(y_pred_raw == 1, 0, 1)
    
    accuracy = accuracy_score(y_test, y_pred)
    
    if np.sum(y_pred) == 0:
        precision = recall = f1 = 0.0
        print("Warning: No attacks detected!")
    else:
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
    
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"Prediction time: {prediction_time:.4f}s")
    
    cm = confusion_matrix(y_test, y_pred)
    print(f"\nConfusion Matrix:")
    print(f"  TN: {cm[0,0]:>6,}  FP: {cm[0,1]:>6,}")
    print(f"  FN: {cm[1,0]:>6,}  TP: {cm[1,1]:>6,}")
    
    print(f"\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK'], zero_division=0))
    
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
    print("One-Class SVM Training")
    print("=" * 60)
    
    data = prepare_data_for_models()
    model, training_time = train_one_class_svm(data['X_train'], data['y_train'])
    
    model_path = 'models/ocsvm_model.pkl'
    joblib.dump(model, model_path)
    print(f"\n✓ Model saved to {model_path}")
    
    print("\n" + "=" * 60)
    print("Model Evaluation")
    print("=" * 60)
    
    train_results = evaluate_model(model, data['X_train'], data['y_train'], "Training Set")
    seen_results = evaluate_model(model, data['X_test_seen'], data['y_test_seen'], "Test Set (Seen Attacks)")
    unseen_results = evaluate_model(model, data['X_test_unseen'], data['y_test_unseen'], "Test Set (Unseen Attacks)")
    
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
        'model_name': 'One-Class SVM',
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
    results_path = 'results/ocsvm_results.json'
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
