#!/usr/bin/env python3
"""
train_real.py
AI-Powered Threat Detection System
Trains XGBoost on real benchmark datasets (CICIDS-2017 / UNSW-NB15)
instead of the synthetic ELK-schema generator used by train.py.

Usage:
  python src/train_real.py --source cicids --data ../lab/datasets/kaggle/cicids2017 --model-dir ../models/cicids2017
  python src/train_real.py --source unsw  --data ../lab/datasets/kaggle --model-dir ../models/unsw_nb15
"""

import argparse
import json
import logging
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OrdinalEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from xgboost import XGBClassifier

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('train_real')

NON_FEATURE_COLS = {
    'src_ip', 'dst_ip', 'src ip', 'dst ip', 'src ip dec', 'dst ip dec',
    'flow id', 'timestamp', 'label', 'attempted category', 'id',
    'attack_cat',
}

LABEL_COLS = {'label', 'attack_cat'}


def _pick_label_col(columns) -> str:
    lowered = {c.strip().lower(): c for c in columns}
    pref = ['label', 'attack_cat']
    for want in pref:
        if want in lowered:
            return lowered[want]
    return pref[0]


def to_binary_label(label_series: pd.Series) -> pd.Series:
    """Map multi-class / string labels to binary int (1 = attack, 0 = benign)."""
    norm = label_series.astype(str).str.strip().str.lower()
    benign_tokens = {'benign', 'normal', '0', '0.0', '00'}
    return (~norm.isin(benign_tokens)).astype(int)


def load_frame(path: Path, max_rows_per_label: int, label_col: str, dedupe: bool = False) -> pd.DataFrame:
    """Load one csv/parquet file, down-sampled per label to bound memory/time."""
    if path.suffix == '.parquet':
        df = pd.read_parquet(path)
    else:
        df = pd.read_csv(path, low_memory=False)

    if dedupe:
        feat_cols = [c for c in df.columns if c != label_col]
        before = len(df)
        df = df.drop_duplicates(subset=feat_cols)
        df = df.reset_index(drop=True)
        if len(df) < before:
            logger.info(f'{path.name}: dropped {before - len(df):,} duplicate rows')

    y = to_binary_label(df[label_col]).astype(int)
    keep_index = []
    for cls in sorted(y.unique()):
        idx = y[y == cls].index
        n = len(idx)
        if n > max_rows_per_label:
            idx = idx[np.random.RandomState(42).choice(n, max_rows_per_label, replace=False)]
        keep_index.extend(idx)
    df = df.loc[keep_index]
    return df


def discover_inputs(data_arg: str, source: str) -> list:
    path = Path(data_arg)
    if path.is_file():
        return [path]
    files = sorted(path.glob('*.csv')) + sorted(path.glob('*.parquet'))
    files = [f for f in files if not f.name.startswith('.')]
    if source == 'cicids':
        # _plus files are exact duplicates; monday is all-benign (no training signal)
        files = [f for f in files if '_plus' not in f.name and f.name.lower() != 'monday.csv']
    if source == 'unsw':
        files = [f for f in files if 'UNSW' in f.name or 'unsw' in f.name]
    return files


def prepare(df: pd.DataFrame, label_col: str, drop_cols: set, encoder=None):
    """Drop non-feature cols, coerce numerics, ordinal-encode the rest.

    Pass an already-fitted encoder to transform a test set with the same
    categories seen in training (unseen values -> -1)."""
    lower = {c.strip().lower(): c for c in df.columns}
    drop = {lower[c] for c in drop_cols if c in lower}
    drop.add(label_col)
    drop = {c for c in drop if c is not None}

    X = df[[c for c in df.columns if c not in drop]].copy()
    X = X.replace([np.inf, -np.inf], np.nan)

    numeric = X.select_dtypes(include=[np.number]).columns
    X[numeric] = X[numeric].fillna(0)

    obj = [c for c in X.columns if not pd.api.types.is_numeric_dtype(X[c])]
    if obj:
        if encoder is None:
            encoder = OrdinalEncoder(handle_unknown='use_encoded_value', unknown_value=-1)
            X[obj] = encoder.fit_transform(X[obj].astype(str))
        else:
            X[obj] = encoder.transform(X[obj].astype(str))
    return X, encoder


DAY_ORDER = {'monday': 0, 'tuesday': 1, 'wednesday': 2, 'thursday': 3, 'friday': 4}


def main():
    p = argparse.ArgumentParser(description='Train threat detection on real datasets')
    p.add_argument('--source', required=True, choices=['cicids', 'unsw'])
    p.add_argument('--data', required=True, help='CSV/parquet file or directory')
    p.add_argument('--model-dir', required=True, help='Where to save model artifacts')
    p.add_argument('--max-rows-per-label', type=int, default=500000)
    p.add_argument('--test-size', type=float, default=0.2)
    p.add_argument('--trees', type=int, default=300)
    p.add_argument('--split', choices=['random', 'temporal', 'official'], default='random',
                   help='random: row-level split (leaky, avoid for headline numbers). '
                        'temporal: hold out whole day(s) (CICIDS). '
                        'official: train/test set files (UNSW-NB15 protocol).')
    p.add_argument('--test-days', default='friday',
                   help='Comma-separated day stems to hold out for --split temporal')
    p.add_argument('--no-dedupe', action='store_true', help='Disable exact-duplicate row removal')
    args = p.parse_args()

    files = discover_inputs(args.data, args.source)
    if not files:
        logger.error(f'No data files found under {args.data}')
        sys.exit(1)

    # Probe first file for label column
    probe = pd.read_parquet(files[0]) if files[0].suffix == '.parquet' else pd.read_csv(files[0], nrows=5, low_memory=False)
    colset = {c.strip().lower() for c in probe.columns}
    if not any(c in colset for c in LABEL_COLS):
        logger.error(f'No label column in {files[0]}. Columns: {list(probe.columns)}')
        sys.exit(1)
    label_col = _pick_label_col(probe.columns)

    if args.split == 'official':
        train_files = [f for f in files if 'train' in f.stem.lower()]
        test_files = [f for f in files if 'test' in f.stem.lower()]
        if not train_files or not test_files:
            logger.error('official split requires separate *training* and *testing* files')
            sys.exit(1)
        logger.info(f'Official split: train={[f.name for f in train_files]} test={[f.name for f in test_files]}')
    elif args.split == 'temporal':
        holdouts = {d.strip().lower() for d in args.test_days.split(',')}
        train_files = [f for f in files if f.stem.lower() not in holdouts]
        test_files = [f for f in files if f.stem.lower() in holdouts]
        if not test_files:
            logger.error(f'temporal split: no files matched test-days {args.test_days}')
            sys.exit(1)
        logger.info(f'Temporal split: hold out {[f.name for f in test_files]}')
    else:
        train_files = test_files = files

    dedupe = not args.no_dedupe
    frames = [load_frame(f, args.max_rows_per_label, label_col, dedupe) for f in train_files]
    df_train = pd.concat(frames, ignore_index=True)
    logger.info(f'Train: {len(df_train):,} rows from {len(frames)} file(s), label col={label_col!r}')

    X_train_raw, cat_encoder = prepare(df_train, label_col, NON_FEATURE_COLS, encoder=None)
    y_train = to_binary_label(df_train[label_col]).astype(int)

    if args.split == 'random':
        X_train_raw, X_test_raw, y_train, y_test = train_test_split(
            X_train_raw, y_train, test_size=args.test_size, stratify=y_train, random_state=42)
    else:
        frames = [load_frame(f, args.max_rows_per_label, label_col, dedupe) for f in test_files]
        df_test = pd.concat(frames, ignore_index=True)
        logger.info(f'Test:  {len(df_test):,} rows from {len(frames)} file(s)')
        X_test_raw, _ = prepare(df_test, label_col, NON_FEATURE_COLS, encoder=cat_encoder)
        # align test columns to training order (categorical counts can differ per day)
        X_test_raw = X_test_raw.reindex(columns=X_train_raw.columns).fillna(0)
        y_test = to_binary_label(df_test[label_col]).astype(int)

    logger.info(f'Features: {X_train_raw.shape[1]} | attacks {int(y_train.sum()):,} / benign {int((1 - y_train).sum()):,}')

    scaler = StandardScaler().fit(X_train_raw)
    X_train, X_test = scaler.transform(X_train_raw), scaler.transform(X_test_raw)

    pos_weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
    model = XGBClassifier(n_estimators=args.trees, max_depth=6, learning_rate=0.1,
                          subsample=0.8, colsample_bytree=0.8,
                          objective='binary:logistic', eval_metric='aucpr',
                          scale_pos_weight=pos_weight, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    metrics = {
        'dataset': args.source,
        'split': args.split,
        'rows_trained': len(X_train),
        'rows_tested': len(X_test),
        'attacks_in_train': int(y_train.sum()),
        'accuracy': float(accuracy_score(y_test, y_pred)),
        'precision': float(precision_score(y_test, y_pred)),
        'recall': float(recall_score(y_test, y_pred)),
        'f1': float(f1_score(y_test, y_pred)),
        'auc_roc': float(roc_auc_score(y_test, y_prob)),
        'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
        'scale_pos_weight': float(pos_weight),
    }
    logger.info(f'acc={metrics["accuracy"]:.4f} prec={metrics["precision"]:.4f} '
                f'recall={metrics["recall"]:.4f} f1={metrics["f1"]:.4f} auc={metrics["auc_roc"]:.4f}')

    out = Path(args.model_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / 'xgboost_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    with open(out / 'feature_scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    if cat_encoder is not None:
        with open(out / 'category_encoder.pkl', 'wb') as f:
            pickle.dump(cat_encoder, f)
    (out / 'feature_columns.json').write_text(json.dumps(X_train_raw.columns.tolist()))
    (out / 'training_metrics.json').write_text(json.dumps(metrics, indent=2))
    logger.info(f'Saved artifacts + metrics to {out}')

    # Self-check: reload artifacts and predict on held-out rows
    with open(out / 'xgboost_model.pkl', 'rb') as f:
        loaded = pickle.load(f)
    cols = json.loads((out / 'feature_columns.json').read_text())
    cols_in_X = X_test.shape[1] == len(cols)
    preds = loaded.predict(X_test[:20])
    ok = cols_in_X and preds.shape == (20,) and set(np.unique(preds)).issubset({0, 1})
    if not ok:
        logger.error('Self-check failed')
        sys.exit(1)
    logger.info('Self-check OK: artifacts reload + predict fine')


if __name__ == '__main__':
    main()