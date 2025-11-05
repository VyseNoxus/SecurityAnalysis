"""
XGBoost Model Training and Evaluation
Gradient Boosting for intrusion detection
"""

import numpy as np
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
import joblib
import time
import json
import os
from feature_engineering import prepare_data_for_models

def train_xgboost(X_train, y_train):
    print("\n" + "=" * 60)
    print("Training XGBoost Model")
    print("=" * 60)
    
    params = {
        'objective': 'binary:logistic',
        'max_depth': 6,
        'learning_rate': 0.1,
        'n_estimators': 100,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'random_state': 42,
        'eval_metric': 'logloss'
    }
    
    print("\nModel parameters:")
    for key, value in params.items():
        print(f"  {key}: {value}")
    
    print("\nTraining...")
    start_time = time.time()
    
    model = xgb.XGBClassifier(**params)
    model.fit(X_train, y_train, verbose=False)
    
    training_time = time.time() - start_time
    print(f"✓ Training completed in {training_time:.2f} seconds")
    
    return model, training_time

def evaluate_model(model, X_test, y_test, dataset_name):
    print(f"\n{dataset_name} Evaluation:")
    print("-" * 60)
    
    start_time = time.time()
    y_pred = model.predict(X_test)
    prediction_time = time.time() - start_time
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
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
    print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']))
    
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
    print("XGBoost Training")
    print("=" * 60)
    
    data = prepare_data_for_models()
    model, training_time = train_xgboost(data['X_train'], data['y_train'])
    
    model_path = 'models/xgboost_model.pkl'
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
        'model_name': 'XGBoost',
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
    results_path = 'results/xgboost_results.json'
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
