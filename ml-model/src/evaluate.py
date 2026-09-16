#!/usr/bin/env python3
"""
evaluate.py
AI-Powered Threat Detection System
Model evaluation and reporting
"""

import os
import sys
import json
import pickle
import logging
from pathlib import Path
from typing import Dict, Any

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
    roc_curve,
    precision_recall_curve
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ModelEvaluator:
    """Model evaluation and reporting"""
    
    def __init__(self, model_dir: str = "ml-model/models"):
        """Initialize evaluator"""
        self.model_dir = Path(model_dir)
        self.model = None
        self.scaler = None
        self.label_encoder = None
        
        self._load_model()
    
    def _load_model(self):
        """Load trained model and preprocessing objects"""
        logger.info("Loading model...")
        
        # Load model
        model_path = self.model_dir / "xgboost_model.pkl"
        if model_path.exists():
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            logger.info(f"Model loaded from {model_path}")
        
        # Load scaler
        scaler_path = self.model_dir / "feature_scaler.pkl"
        if scaler_path.exists():
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
        
        # Load label encoder
        encoder_path = self.model_dir / "label_encoder.pkl"
        if encoder_path.exists():
            with open(encoder_path, 'rb') as f:
                self.label_encoder = pickle.load(f)
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Evaluate model performance"""
        logger.info("Evaluating model...")
        
        if self.model is None:
            raise ValueError("Model not loaded")
        
        # Scale features
        if self.scaler:
            X_test_scaled = self.scaler.transform(X_test)
        else:
            X_test_scaled = X_test
        
        # Make predictions
        y_pred = self.model.predict(X_test_scaled)
        y_prob = self.model.predict_proba(X_test_scaled)[:, 1]
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted'),
            'recall': recall_score(y_test, y_pred, average='weighted'),
            'f1': f1_score(y_test, y_pred, average='weighted'),
            'auc_roc': roc_auc_score(y_test, y_prob),
            'confusion_matrix': confusion_matrix(y_test, y_pred),
            'classification_report': classification_report(y_test, y_pred),
            'y_test': y_test,
            'y_pred': y_pred,
            'y_prob': y_prob
        }
        
        return metrics
    
    def plot_roc_curve(self, y_test: np.ndarray, y_prob: np.ndarray, output_path: str):
        """Plot ROC curve"""
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, color='blue', lw=2, label=f'ROC curve (AUC = {roc_auc_score(y_test, y_prob):.3f})')
        plt.plot([0, 1], [0, 1], color='gray', linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic (ROC) Curve')
        plt.legend(loc="lower right")
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        plt.close()
        logger.info(f"ROC curve saved to {output_path}")
    
    def plot_precision_recall_curve(self, y_test: np.ndarray, y_prob: np.ndarray, output_path: str):
        """Plot precision-recall curve"""
        precision, recall, _ = precision_recall_curve(y_test, y_prob)
        
        plt.figure(figsize=(8, 6))
        plt.plot(recall, precision, color='blue', lw=2, label='Precision-Recall curve')
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curve')
        plt.legend(loc="lower left")
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        plt.close()
        logger.info(f"Precision-recall curve saved to {output_path}")
    
    def plot_confusion_matrix(self, confusion_matrix: np.ndarray, output_path: str):
        """Plot confusion matrix"""
        plt.figure(figsize=(8, 6))
        sns.heatmap(
            confusion_matrix,
            annot=True,
            fmt='d',
            cmap='Blues',
            xticklabels=['Benign', 'Malicious'],
            yticklabels=['Benign', 'Malicious']
        )
        plt.title('Confusion Matrix')
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        plt.close()
        logger.info(f"Confusion matrix saved to {output_path}")
    
    def generate_report(self, metrics: Dict[str, Any], output_dir: str):
        """Generate evaluation report"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save metrics
        metrics_save = {
            'accuracy': metrics['accuracy'],
            'precision': metrics['precision'],
            'recall': metrics['recall'],
            'f1': metrics['f1'],
            'auc_roc': metrics['auc_roc']
        }
        
        with open(output_path / "evaluation_metrics.json", 'w') as f:
            json.dump(metrics_save, f, indent=2)
        
        # Save classification report
        with open(output_path / "classification_report.txt", 'w') as f:
            f.write(metrics['classification_report'])
        
        # Plot curves
        self.plot_roc_curve(
            metrics['y_test'],
            metrics['y_prob'],
            str(output_path / "roc_curve.png")
        )
        
        self.plot_precision_recall_curve(
            metrics['y_test'],
            metrics['y_prob'],
            str(output_path / "precision_recall_curve.png")
        )
        
        self.plot_confusion_matrix(
            metrics['confusion_matrix'],
            str(output_path / "confusion_matrix.png")
        )
        
        logger.info(f"Evaluation report saved to {output_path}")
    
    def print_summary(self, metrics: Dict[str, Any]):
        """Print evaluation summary"""
        print("\n" + "="*60)
        print("MODEL EVALUATION SUMMARY")
        print("="*60)
        
        print(f"\nAccuracy:  {metrics['accuracy']:.4f}")
        print(f"Precision: {metrics['precision']:.4f}")
        print(f"Recall:    {metrics['recall']:.4f}")
        print(f"F1 Score:  {metrics['f1']:.4f}")
        print(f"AUC-ROC:   {metrics['auc_roc']:.4f}")
        
        print("\nClassification Report:")
        print(metrics['classification_report'])
        
        print("="*60)


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Evaluate threat detection model')
    parser.add_argument('--model-dir', default='ml-model/models', help='Model directory')
    parser.add_argument('--data', required=True, help='Path to test data CSV')
    parser.add_argument('--output-dir', default='ml-model/evaluation', help='Output directory')
    
    args = parser.parse_args()
    
    # Create evaluator
    evaluator = ModelEvaluator(model_dir=args.model_dir)
    
    # Load data
    logger.info(f"Loading data from {args.data}")
    df = pd.read_csv(args.data)
    
    # Extract features (simplified for evaluation)
    # In production, use the same feature extraction as training
    from train import ThreatDetectionTrainer
    trainer = ThreatDetectionTrainer(model_dir=args.model_dir)
    
    X = trainer.extract_features(df)
    
    if 'label' in df.columns:
        y = trainer.label_encoder.transform(df['label'])
    else:
        y = np.zeros(len(df))
    
    # Split data
    from sklearn.model_selection import train_test_split
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Evaluate
    try:
        metrics = evaluator.evaluate(X_test, y_test)
        evaluator.print_summary(metrics)
        evaluator.generate_report(metrics, args.output_dir)
        print("\n✅ Evaluation completed successfully!")
    except Exception as e:
        logger.error(f"Evaluation failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()