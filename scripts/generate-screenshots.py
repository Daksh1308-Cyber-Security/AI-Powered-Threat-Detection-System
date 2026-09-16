#!/usr/bin/env python3
"""
generate-screenshots.py
AI-Powered Threat Detection System
Generates portfolio screenshots that don't require the lab (detection coverage,
alert volume, model ROC curve, attack simulation timeline) into docs/screenshots/.
Kibana screenshots are captured manually after the lab is provisioned.
"""

import sys
import pickle
from pathlib import Path
from collections import Counter

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'ml-model' / 'src'))
OUT = ROOT / 'docs' / 'screenshots'
OUT.mkdir(parents=True, exist_ok=True)

SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']


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
    """Daily alert volume from the simulated lab dataset."""
    df = pd.read_csv(ROOT / 'lab' / 'datasets' / 'sample_logs.csv')
    df['@timestamp'] = pd.to_datetime(df['@timestamp'])
    df['day'] = df['@timestamp'].dt.date
    daily = df.groupby(['day', 'label']).size().unstack(fill_value=0)
    daily = daily.reindex(columns=['benign', 'attack'], fill_value=0)

    fig, ax = plt.subplots(figsize=(10, 5))
    daily['benign'] = daily['benign'].astype(int)
    daily['attack'] = daily['attack'].astype(int)
    x = range(len(daily))
    ax.bar(x, daily['benign'], label='Benign', color='#4caf50', alpha=0.85)
    ax.bar(x, daily['attack'], bottom=daily['benign'], label='Attack', color='#e53935', alpha=0.9)
    ax.set_xticks(list(x))
    ax.set_xticklabels([d.isoformat() if isinstance(d, (pd.Timestamp, object)) else str(d) for d in daily.index], rotation=30)
    ax.set_title('Alert Volume Trend (Simulated Lab Dataset)')
    ax.set_xlabel('Date')
    ax.set_ylabel('Events')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT / 'alert_volume_trend.png', dpi=150)
    plt.close()


def generate_roc_curve():
    """ROC curve of the trained XGBoost model on the simulated dataset."""
    from evaluate import ModelEvaluator
    from train import ThreatDetectionTrainer

    model_dir = ROOT / 'ml-model' / 'models'
    df = pd.read_csv(ROOT / 'lab' / 'datasets' / 'sample_logs.csv')
    trainer = ThreatDetectionTrainer(model_dir=str(model_dir))
    X = trainer.extract_features(df)
    y = trainer.label_encoder.transform(df['label'])
    evaluator = ModelEvaluator(model_dir=str(model_dir))
    metrics = evaluator.evaluate(X, y)
    evaluator.plot_roc_curve(metrics['y_test'], metrics['y_prob'], str(OUT / 'roc_curve.png'))

    with open(model_dir / 'training_metrics.json') as f:
        training = __import__('json').load(f)
    print(f"AUC-ROC (synthetic holdout): {metrics['auc_roc']:.3f} | trained AUC: {training.get('auc_roc', 'n/a')}")


def generate_attack_timeline():
    """Attack event timeline from the simulated lab dataset."""
    df = pd.read_csv(ROOT / 'lab' / 'datasets' / 'sample_logs.csv')
    df['@timestamp'] = pd.to_datetime(df['@timestamp'])
    attacks = df[df['label'] == 'attack'].copy()
    attacks['type'] = attacks['attack_name'].fillna('unknown').astype(str)

    order = sorted(attacks['type'].unique())
    y = [order.index(t) for t in attacks['type']]
    fig, ax = plt.subplots(figsize=(11, 5))
    colors = plt.cm.tab20([order.index(t) / max(1, len(order)) for t in attacks['type']])
    ax.scatter(attacks['@timestamp'], y, c=colors, s=18, alpha=0.8)
    ax.set_yticks(range(len(order)))
    ax.set_yticklabels(order, fontsize=8)
    ax.set_title('Attack Simulation Timeline')
    ax.set_xlabel('Timestamp')
    ax.set_ylabel('Attack Type')
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