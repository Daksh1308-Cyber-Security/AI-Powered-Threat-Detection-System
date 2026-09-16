#!/usr/bin/env python3
"""
generate-architecture.py
AI-Powered Threat Detection System
Renders the system architecture diagram to docs/screenshots/architecture.png.
"""

from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'docs' / 'screenshots'
OUT.mkdir(parents=True, exist_ok=True)

LAYERS = [
    ("ATTACK SIMULATION", [
        ("Kali Attacker\n192.168.56.10\nnmap / hydra / sqlmap / msf", "T"),
        ("Debian Target\n192.168.56.20\nSSH + Apache + Suricata", "T"),
        ("Host Services\n192.168.56.1\nDVWA web app", "T"),
    ], True),
    ("ELK STACK", [
        ("Logstash\nlinux-syslog :5514\nauth :5046  beats :5044", "T"),
        ("Elasticsearch\nlinux-*  attack-simulations\ndetection-alerts", "T"),
        ("Kibana\nSOC Overview · MITRE\nAttack Timeline", None),
    ], True),
    ("DETECTION ENGINE", [
        ("Sigma Rules\n51 · MITRE mapped", None),
        ("YARA Rules\n20 · malware patterns", None),
        ("ML Model\nXGBoost · UNSW-NB15 +\nCICIDS-2017", None),
    ], True),
    ("AUTOMATION & RESPONSE", [
        ("Alert Triage\nscore = ML(40) +\nSigma(30) + YARA(20) + MITRE(10)", "B"),
        ("IR Playbooks\nauto incident\nresponse docs", "B"),
        ("SOC Dashboard\nStreamlit · real-time\nalert feed + metrics", "B"),
    ], True),
]

BUBBLE = "#0ea5e9"
LAYER_H, N_H = 2.6, 1.55
CENTERS = [2, 6.5, 11]
Y_TOP = 12.6
GAP = 0.9


def box(ax, x, y, w, h, text):
    rect = matplotlib.patches.FancyBboxPatch(
        (x - w / 2, y - h / 2), w, h,
        boxstyle="round,pad=0.02", fc="#334155", ec="#475569", lw=1)
    ax.add_patch(rect)
    ax.text(x, y, text, ha='center', va='center', fontsize=10, color='white', fontweight='bold')


def arrow(ax, x0, y0, x1, y1):
    ax.annotate('', xy=(x1, y1), xytext=(x0, y0),
                arrowprops=dict(arrowstyle='-|>', color='#334155', lw=1.4))


def box_bottom_y(layer_idx):
    return Y_TOP - (LAYER_H + GAP) * layer_idx - LAYER_H


def layer_center_y(layer_idx):
    return Y_TOP - (LAYER_H + GAP) * layer_idx - LAYER_H / 2


fig, ax = plt.subplots(figsize=(13, 9))
ax.set_xlim(0, 13)
ax.set_ylim(0, 13)
ax.axis('off')

for layer_idx, (name, members, _) in enumerate(LAYERS):
    y_bot = box_bottom_y(layer_idx)
    rect = matplotlib.patches.FancyBboxPatch(
        (0.15, y_bot), 12.7, LAYER_H, boxstyle="round,pad=0.01",
        fc="#f8fafc", ec="#94a3b8", lw=1.2)
    ax.add_patch(rect)
    ax.text(0.4, Y_TOP - (LAYER_H + GAP) * layer_idx - 0.38, name,
            ha='left', va='center', fontsize=12, fontweight='bold', color=BUBBLE)
    for (text, _), cx in zip(members, CENTERS):
        box(ax, cx, layer_center_y(layer_idx), 3.1, N_H, text)

for i in range(3):
    for cx in CENTERS:
        arrow(ax, cx, box_bottom_y(i) - 0.45, cx, box_bottom_y(i + 1) + 0.45)

plt.tight_layout(pad=0.5)
f = OUT / 'architecture.png'
plt.savefig(f, dpi=150, bbox_inches='tight', facecolor='white')
plt.close()
print(f'Wrote {f}')