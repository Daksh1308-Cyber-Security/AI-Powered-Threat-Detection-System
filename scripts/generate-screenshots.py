#!/usr/bin/env python3
"""
generate-screenshots.py
AI-Powered Threat Detection System
Generates portfolio screenshots from REAL data and REAL trained models
into docs/screenshots/. No synthetic data is used for ML visuals.
"""

import sys
import pickle
from pathlib import Path
from collections import Counter

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'docs' / 'screenshots'
OUT.mkdir(parents=True, exist_ok=True)

SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']
CICIDS_DIR = ROOT / 'lab' / 'datasets' / 'kaggle' / 'cicids2017'


def generate_mitre_heatmap():
    """Tactic x severity coverage matrix from the Sigma rules."""
    rule_dir = ROOT / 'detection-rules' / 'sigma' / 'rules'
    counts = Counter()
    tactic_names = []
    severity_levels = []
    for folder in sorted(rule_dir.iterdir()):
        if not folder.is_dir():
            continue
        tactic_name = ' '.join(folder.name.split('_')[1:])
        tactic_names.append(tactic_name)
        for rule in folder.glob('*.yml'):
            level = severity_levels
            from yaml import safe_load
            with open(rule, 'r') as f:
                data = safe_load(f)
            level = data.get('level', 'low')
            counts[(tactic_name, level)] += 1

    matrix = []
    for tactic in tactic_names:
        matrix.append([counts[(tactic, s)] for s in SEVERITY_ORDER])

    fig, ax = plt.subplots(figsize=(10, 6))
    im = ax.imshow(matrix, cmap='Greens', aspect='auto')
    ax.set_xticks(range(len(SEVERITY_ORDER)))
    ax.set_xticklabels([s.title() for s in SEVERITY_ORDER])
    ax.set_yticks(range(len(tactic_names)))
    ax.set_yticklabels(tactic_names)
    for i in range(len(tactic_names)):
        for j in range(len(SEVERITY_ORDER)):
            ax.text(j, i, matrix[i][j], ha='center', va='center', color='black')
    ax.set_title('MITRE ATT&CK Coverage Heatmap (51 Sigma Rules)')
    ax.set_xlabel('Severity')
    ax.set_ylabel('Tactic')
    plt.colorbar(im, label='Rule count')
    plt.tight_layout()
    plt.savefig(OUT / 'mitre_attck_heatmap.png', dpi=150)
    plt.close()


def generate_alert_volume_trend():
    """Real per-day attack/benign flow volume from the CICIDS-2017 testbed."""
    daily = []
    for day in ['tuesday', 'wednesday', 'thursday', 'friday']:
        df = pd.read_csv(CICIDS_DIR / f'{day}.csv', low_memory=False, usecols=['Label'])
        lab = df['Label'].str.strip().str.lower()
        daily.append({'day': day.title(), 'benign': int((lab == 'benign').sum()),
                      'attack': int((lab != 'benign').sum())})
    d = pd.DataFrame(daily)

    fig, ax = plt.subplots(figsize=(10, 5))
    x = range(len(d))
    ax.bar(x, d['benign'], label='Benign', color='#4caf50', alpha=0.85)
    ax.bar(x, d['attack'], bottom=d['benign'], label='Attack', color='#e53935', alpha=0.9)
    ax.set_xticks(list(x))
    ax.set_xticklabels(d['day'])
    ax.set_title('Labeled Flow Volume by Day (CICIDS-2017)')
    ax.set_xlabel('Capture Day')
    ax.set_ylabel('Flows')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT / 'alert_volume_trend.png', dpi=150)
    plt.close()


def generate_roc_curve():
    """ROC curve of the REAL model trained on UNSW-NB15 (official split)."""
    model_dir = ROOT / 'ml-model' / 'models' / 'unsw_nb15'
    npz = np.load(model_dir / 'test_predictions.npz')
    y_test, y_prob = npz['y_test'], npz['y_prob']
    with open(model_dir / 'training_metrics.json') as f:
        import json
        m = json.load(f)

    from sklearn.metrics import roc_curve, roc_auc_score
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    auc = roc_auc_score(y_test, y_prob)
    fig, ax = plt.subplots(figsize=(6, 6))
    ax.plot(fpr, tpr, lw=2, color='#0ea5e9', label=f'AUC = {auc:.3f}')
    ax.plot([0, 1], [0, 1], '--', color='#94a3b8')
    ax.set_xlabel('False Positive Rate')
    ax.set_ylabel('True Positive Rate')
    ax.set_title('ML Model ROC — UNSW-NB15 (official split)')
    ax.legend(loc='lower right')
    plt.tight_layout()
    plt.savefig(OUT / 'roc_curve.png', dpi=150)
    plt.close()
    print(f"AUC-ROC (real, UNSW-NB15 official split): {auc:.3f}")


def generate_attack_timeline():
    """Real attack-class timeline from the CICIDS-2017 labeled flows."""
    recs = []
    for day in ['tuesday', 'wednesday', 'thursday', 'friday']:
        df = pd.read_csv(CICIDS_DIR / f'{day}.csv', low_memory=False, usecols=['Label'])
        lab = df['Label'].str.strip().str.lower()
        for cls, n in lab[lab != 'benign'].value_counts().items():
            recs.append({'day': day.title(), 'cls': cls, 'n': int(n)})
    d = pd.DataFrame(recs)

    classes = sorted(d['cls'].unique())
    ymap = {c: i for i, c in enumerate(classes)}
    fig, ax = plt.subplots(figsize=(11, 6))
    for day in d['day'].unique():
        sub = d[d['day'] == day]
        ax.scatter([day] * len(sub), [ymap[c] for c in sub['cls']],
                   s=sub['n'] / sub['n'].max() * 300 + 20, alpha=0.7, edgecolor='black', linewidth=0.4)
    ax.set_yticks(range(len(classes)))
    ax.set_yticklabels(classes, fontsize=8)
    ax.set_title('Attack Classes Present per Day (CICIDS-2017, real testbed traffic)')
    ax.set_xlabel('Capture Day')
    ax.set_ylabel('Attack Class')
    ax.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT / 'attack_simulation_timeline.png', dpi=150)
    plt.close()


if __name__ == '__main__':
    generate_mitre_heatmap()
    generate_alert_volume_trend()
    generate_roc_curve()
    generate_attack_timeline()
    print(f"Wrote screenshots to {OUT}")