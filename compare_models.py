"""
Model Comparison and Visualization
Compares XGBoost, One-Class SVM, and LSTM performance on intrusion detection
"""

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

def load_results():
    results = {
        'XGBoost': {},
        'One-Class SVM': {},
        'LSTM': {}
    }
    return results

def create_comparison_table(results):
    data = []
    
    for model_name, model_results in results.items():
        if model_results:
            row = {
                'Model': model_name,
                'Train Acc': model_results.get('train_accuracy', 0),
                'Test Seen Acc': model_results.get('seen_accuracy', 0),
                'Test Unseen Acc': model_results.get('unseen_accuracy', 0),
                'Train F1': model_results.get('train_f1', 0),
                'Test Seen F1': model_results.get('seen_f1', 0),
                'Test Unseen F1': model_results.get('unseen_f1', 0),
                'Training Time (s)': model_results.get('training_time', 0)
            }
            data.append(row)
    
    return pd.DataFrame(data)

def plot_comparison(results, save_dir='results'):
    os.makedirs(save_dir, exist_ok=True)
    
    models = list(results.keys())
    
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    fig.suptitle('Model Performance Comparison', fontsize=16, fontweight='bold')
    
    # Accuracy comparison
    train_acc = [results[m].get('train_accuracy', 0) for m in models]
    seen_acc = [results[m].get('seen_accuracy', 0) for m in models]
    unseen_acc = [results[m].get('unseen_accuracy', 0) for m in models]
    
    x = np.arange(len(models))
    width = 0.25
    
    axes[0, 0].bar(x - width, train_acc, width, label='Training', alpha=0.8)
    axes[0, 0].bar(x, seen_acc, width, label='Test Seen', alpha=0.8)
    axes[0, 0].bar(x + width, unseen_acc, width, label='Test Unseen', alpha=0.8)
    axes[0, 0].set_ylabel('Accuracy')
    axes[0, 0].set_title('Accuracy Comparison')
    axes[0, 0].set_xticks(x)
    axes[0, 0].set_xticklabels(models)
    axes[0, 0].legend()
    axes[0, 0].grid(True, alpha=0.3)
    
    # F1-Score comparison
    train_f1 = [results[m].get('train_f1', 0) for m in models]
    seen_f1 = [results[m].get('seen_f1', 0) for m in models]
    unseen_f1 = [results[m].get('unseen_f1', 0) for m in models]
    
    axes[0, 1].bar(x - width, train_f1, width, label='Training', alpha=0.8)
    axes[0, 1].bar(x, seen_f1, width, label='Test Seen', alpha=0.8)
    axes[0, 1].bar(x + width, unseen_f1, width, label='Test Unseen', alpha=0.8)
    axes[0, 1].set_ylabel('F1-Score')
    axes[0, 1].set_title('F1-Score Comparison')
    axes[0, 1].set_xticks(x)
    axes[0, 1].set_xticklabels(models)
    axes[0, 1].legend()
    axes[0, 1].grid(True, alpha=0.3)
    
    # Generalization gap
    acc_gap = [abs(results[m].get('seen_accuracy', 0) - results[m].get('unseen_accuracy', 0)) for m in models]
    f1_gap = [abs(results[m].get('seen_f1', 0) - results[m].get('unseen_f1', 0)) for m in models]
    
    axes[1, 0].bar(x - width/2, acc_gap, width, label='Accuracy Gap', alpha=0.8)
    axes[1, 0].bar(x + width/2, f1_gap, width, label='F1-Score Gap', alpha=0.8)
    axes[1, 0].set_ylabel('Gap (Seen - Unseen)')
    axes[1, 0].set_title('Generalization Gap (Lower is Better)')
    axes[1, 0].set_xticks(x)
    axes[1, 0].set_xticklabels(models)
    axes[1, 0].legend()
    axes[1, 0].grid(True, alpha=0.3)
    
    # Training time
    training_times = [results[m].get('training_time', 0) for m in models]
    
    axes[1, 1].bar(models, training_times, alpha=0.8, color=['blue', 'green', 'red'])
    axes[1, 1].set_ylabel('Time (seconds)')
    axes[1, 1].set_title('Training Time Comparison')
    axes[1, 1].grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(f'{save_dir}/model_comparison.png', dpi=300, bbox_inches='tight')
    print(f"✓ Comparison plot saved to {save_dir}/model_comparison.png")
    plt.close()
    
    # Precision-Recall comparison
    fig, ax = plt.subplots(figsize=(10, 6))
    
    precision_seen = [results[m].get('seen_precision', 0) for m in models]
    recall_seen = [results[m].get('seen_recall', 0) for m in models]
    precision_unseen = [results[m].get('unseen_precision', 0) for m in models]
    recall_unseen = [results[m].get('unseen_recall', 0) for m in models]
    
    ax.scatter(recall_seen, precision_seen, s=200, alpha=0.6, label='Test Seen', marker='o')
    ax.scatter(recall_unseen, precision_unseen, s=200, alpha=0.6, label='Test Unseen', marker='^')
    
    for i, model in enumerate(models):
        ax.annotate(model, (recall_seen[i], precision_seen[i]), fontsize=10, ha='right')
        ax.annotate(model, (recall_unseen[i], precision_unseen[i]), fontsize=10, ha='right')
    
    ax.set_xlabel('Recall')
    ax.set_ylabel('Precision')
    ax.set_title('Precision-Recall Trade-off')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(f'{save_dir}/precision_recall.png', dpi=300, bbox_inches='tight')
    print(f"✓ Precision-Recall plot saved to {save_dir}/precision_recall.png")
    plt.close()

def generate_summary_report(results, save_dir='results'):
    os.makedirs(save_dir, exist_ok=True)
    
    report = "# Model Comparison Report\n\n"
    report += "## Overview\n"
    report += "Comparison of XGBoost, One-Class SVM, and LSTM for intrusion detection.\n\n"
    
    report += "## Performance Summary\n\n"
    report += "### Test Set (Seen Attacks)\n"
    report += "| Model | Accuracy | Precision | Recall | F1-Score |\n"
    report += "|-------|----------|-----------|--------|----------|\n"
    
    for model_name in results.keys():
        r = results[model_name]
        report += f"| {model_name} | {r.get('seen_accuracy', 0):.4f} | {r.get('seen_precision', 0):.4f} | {r.get('seen_recall', 0):.4f} | {r.get('seen_f1', 0):.4f} |\n"
    
    report += "\n### Test Set (Unseen Attacks)\n"
    report += "| Model | Accuracy | Precision | Recall | F1-Score |\n"
    report += "|-------|----------|-----------|--------|----------|\n"
    
    for model_name in results.keys():
        r = results[model_name]
        report += f"| {model_name} | {r.get('unseen_accuracy', 0):.4f} | {r.get('unseen_precision', 0):.4f} | {r.get('unseen_recall', 0):.4f} | {r.get('unseen_f1', 0):.4f} |\n"
    
    report += "\n### Generalization Analysis\n"
    report += "| Model | Accuracy Gap | F1-Score Gap | Training Time (s) |\n"
    report += "|-------|--------------|--------------|-------------------|\n"
    
    for model_name in results.keys():
        r = results[model_name]
        acc_gap = abs(r.get('seen_accuracy', 0) - r.get('unseen_accuracy', 0))
        f1_gap = abs(r.get('seen_f1', 0) - r.get('unseen_f1', 0))
        report += f"| {model_name} | {acc_gap:.4f} | {f1_gap:.4f} | {r.get('training_time', 0):.2f} |\n"
    
    with open(f'{save_dir}/comparison_report.md', 'w') as f:
        f.write(report)
    
    print(f"✓ Summary report saved to {save_dir}/comparison_report.md")

if __name__ == '__main__':
    print("Model Comparison Script")
    print("Run training scripts first:")
    print("  python train_xgboost.py")
    print("  python train_ocsvm.py")
    print("  python train_lstm.py")
