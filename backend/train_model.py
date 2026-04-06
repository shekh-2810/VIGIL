"""
Vigil - Model Trainer v2
Trains XGBoost classifier on phishing dataset.
Outputs: model/vigil_model.json + model/scaler.pkl + model/model_meta.json

Changes from v1:
  - Early stopping to prevent overfitting
  - Proper holdout validation set (train/val/test split)
  - Flags if F1 = 1.0 (almost certainly overfitting)
  - Better hyperparameters for generalization
"""

import os
import sys
import json
import pickle
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
from features import FEATURE_NAMES

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, precision_score, recall_score, f1_score
)
import xgboost as xgb


def train_model(dataset_path: str = 'data/dataset.csv',
                model_dir: str = 'model'):

    os.makedirs(model_dir, exist_ok=True)
    print("=" * 60)
    print("VIGIL — XGBoost Phishing Classifier Training v2")
    print("=" * 60)

    # ── Load data ─────────────────────────────────────────────
    print(f"\nLoading dataset: {dataset_path}")
    df = pd.read_csv(dataset_path)
    print(f"Shape: {df.shape}")
    print(f"Class distribution:\n{df['label'].value_counts()}\n")

    X = df[FEATURE_NAMES].values
    y = df['label'].values

    # ── Three-way split: 70% train / 15% val / 15% test ──────
    # Val set is used for early stopping, test set for final eval
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )
    print(f"Train: {len(X_train)} | Val: {len(X_val)} | Test: {len(X_test)}")

    # ── Scale features ────────────────────────────────────────
    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_val_sc   = scaler.transform(X_val)
    X_test_sc  = scaler.transform(X_test)

    # ── XGBoost model ─────────────────────────────────────────
    # Tuned for generalization, NOT perfect training accuracy
    model = xgb.XGBClassifier(
        n_estimators=500,          # high — early stopping will cut this down
        max_depth=5,               # shallower than v1 (was 6) → less overfitting
        learning_rate=0.03,        # slower learning → better generalization
        subsample=0.75,            # row sampling per tree
        colsample_bytree=0.7,      # feature sampling per tree
        colsample_bylevel=0.7,     # feature sampling per level
        min_child_weight=5,        # higher → more conservative splits
        gamma=0.2,                 # min loss reduction to split
        reg_alpha=0.5,             # L1 regularization
        reg_lambda=2.0,            # L2 regularization (higher than v1)
        scale_pos_weight=1.0,
        eval_metric='logloss',
        early_stopping_rounds=30,  # in constructor for xgboost >= 1.6
        random_state=42,
        n_jobs=-1,
    )

    print("\nTraining XGBoost model with early stopping...")
    model.fit(
        X_train_sc, y_train,
        eval_set=[(X_train_sc, y_train), (X_val_sc, y_val)],
        verbose=50,
    )

    best_iteration = model.best_iteration
    print(f"\nBest iteration: {best_iteration} (early stopping cut from 500)")

    # ── Evaluation on held-out TEST set ──────────────────────
    y_pred = model.predict(X_test_sc)
    y_prob = model.predict_proba(X_test_sc)[:, 1]

    precision = precision_score(y_test, y_pred)
    recall    = recall_score(y_test, y_pred)
    f1        = f1_score(y_test, y_pred)
    auc       = roc_auc_score(y_test, y_prob)

    print("\n" + "=" * 60)
    print("EVALUATION RESULTS (held-out test set)")
    print("=" * 60)
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1-Score  : {f1:.4f}")
    print(f"AUC-ROC   : {auc:.4f}")

    # Overfitting warning
    if f1 >= 0.999:
        print("\n⚠️  WARNING: F1=1.0 detected — dataset may be too easy.")
        print("   Run build_dataset_v3.py to regenerate a harder dataset.")
    elif f1 >= 0.97:
        print(f"\n✓ Good model — F1={f1:.4f} on realistic phishing patterns.")
    else:
        print(f"\n✓ Model trained — F1={f1:.4f}")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TN={cm[0,0]}  FP={cm[0,1]}")
    print(f"  FN={cm[1,0]}  TP={cm[1,1]}")

    # ── Cross-validation on full dataset ─────────────────────
    print("\nRunning 5-fold cross-validation...")
    scaler_cv = StandardScaler()
    X_sc = scaler_cv.fit_transform(X)

    # Use best_iteration for CV to be fair
    cv_model = xgb.XGBClassifier(
        n_estimators=best_iteration or 200,
        max_depth=5, learning_rate=0.03,
        subsample=0.75, colsample_bytree=0.7, colsample_bylevel=0.7,
        min_child_weight=5, gamma=0.2, reg_alpha=0.5, reg_lambda=2.0,
        eval_metric='logloss', random_state=42, n_jobs=-1,
    )
    cv_scores = cross_val_score(cv_model, X_sc, y, cv=5, scoring='f1')
    print(f"CV F1 scores: {[round(s, 4) for s in cv_scores]}")
    print(f"CV F1 mean:   {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # ── Feature importance ────────────────────────────────────
    importance = model.feature_importances_
    feat_importance = sorted(
        zip(FEATURE_NAMES, importance),
        key=lambda x: x[1], reverse=True
    )
    print("\nTop 15 Most Important Features:")
    for name, score in feat_importance[:15]:
        bar = '█' * int(score * 300)
        print(f"  {name:35s} {score:.4f} {bar}")

    # Health check: no single feature should dominate >60%
    top_score = feat_importance[0][1]
    if top_score > 0.6:
        print(f"\n⚠️  Feature '{feat_importance[0][0]}' dominates at {top_score:.1%}")
        print("   Consider regenerating the dataset with build_dataset_v3.py")

    # ── Save artifacts ────────────────────────────────────────
    model_path  = os.path.join(model_dir, 'vigil_model.json')
    scaler_path = os.path.join(model_dir, 'scaler.pkl')
    meta_path   = os.path.join(model_dir, 'model_meta.json')

    model.save_model(model_path)
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)

    meta = {
        'feature_names': FEATURE_NAMES,
        'n_features': len(FEATURE_NAMES),
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'auc_roc': round(auc, 4),
        'cv_f1_mean': round(float(cv_scores.mean()), 4),
        'cv_f1_std': round(float(cv_scores.std()), 4),
        'best_iteration': best_iteration,
        'top_features': [(n, round(float(s), 4)) for n, s in feat_importance[:10]],
        'thresholds': {'safe': 0.3, 'suspicious': 0.6, 'dangerous': 0.8}
    }
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)

    print(f"\n✓ Model saved:  {model_path}")
    print(f"✓ Scaler saved: {scaler_path}")
    print(f"✓ Meta saved:   {meta_path}")
    print("\nTraining complete!")

    return model, scaler, meta


if __name__ == '__main__':
    train_model()
