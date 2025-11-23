# CICIDS Network Intrusion Detection

Machine learning-based brute force attack detection using the CICIDS2017 Tuesday-WorkingHours dataset.

## Project Overview

This project compares three machine learning approaches for detecting SSH/FTP brute force attacks:
- **XGBoost** - Gradient boosting classifier
- **One-Class SVM** - Anomaly detection (trained only on benign traffic)
- **LSTM** - Deep learning for sequential pattern recognition

The goal is to evaluate which approach best detects brute force attacks and generalizes to unseen attack variants.

## Dataset

The project uses the CICIDS2017 Tuesday-WorkingHours.pcap_ISCX.csv dataset containing:
- **Benign traffic**: Normal network activity
- **FTP-Patator**: FTP brute force attacks
- **SSH-Patator**: SSH brute force attacks

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Prepare the dataset: (Tuesday-WorkingHours.pcap_ISCX)
```bash
python data_preparation.py
python feature_engineering.py
```

3. Testing on external dataset: (02-14-2018.csv)
```bash
python tune_threshold.py
```

## Training Models

Train each model individually:

```bash
# XGBoost
python train_xgboost.py

# One-Class SVM
python train_ocsvm.py

# LSTM
python train_lstm.py
```

## Evaluation

Each training script evaluates the model on:
- **Training set** - Model performance on training data
- **Test set (seen attacks)** - Performance on attack types seen during training
- **Test set (unseen attacks)** - Performance on unseen attack variants (zero-day simulation)

Compare results:
```bash
python compare_models.py
```

## Web Dashboard

Launch the interactive web dashboard to visualize and compare model results:

```bash
python app.py
```

Then open your browser to `http://localhost:5000`

The dashboard features:
- **Model Comparison View**: Compare all three models side-by-side
- **Individual Model View**: Deep dive into each model's performance
- **Interactive Charts**: Accuracy, F1-Score, Precision, Recall comparisons
- **Generalization Analysis**: See how models perform on unseen attacks
- **Confusion Matrices**: Visual representation of classification results
- **Dropdown Selection**: Easily switch between models

## Project Structure

```
SecurityAnalysis/
├── data/
│   └── processed/              # Processed datasets
│       ├── train.csv           # Training set (60%)
│       ├── test_seen.csv       # Test set - seen attacks (20%)
│       ├── test_unseen.csv     # Test set - unseen attacks (20%)
│       └── test_full.csv       # Complete test set
├── models/                     # Trained models
├── results/                    # Results and visualizations
│   ├── xgboost_results.json    # XGBoost metrics
│   ├── ocsvm_results.json      # One-Class SVM metrics
│   └── lstm_results.json       # LSTM metrics
├── templates/                  # Flask web templates
│   └── index.html              # Dashboard UI
├── Tuesday-WorkingHours.pcap_ISCX.csv  # Raw dataset
├── data_preparation.py         # Data cleaning and splitting
├── feature_engineering.py      # Feature preprocessing
├── train_xgboost.py           # XGBoost training
├── train_ocsvm.py             # One-Class SVM training
├── train_lstm.py              # LSTM training
├── compare_models.py          # Model comparison
├── app.py                     # Flask web dashboard
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## Evaluation Metrics

- **Accuracy**: Overall correctness
- **Precision**: True positives / (True positives + False positives)
- **Recall**: True positives / (True positives + False negatives)
- **F1-Score**: Harmonic mean of precision and recall
- **Generalization Gap**: Performance difference between seen and unseen attacks
