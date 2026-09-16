#!/usr/bin/env python3
"""
train.py
AI-Powered Threat Detection System
XGBoost model training for anomaly detection
"""

import os
import sys
import json
import pickle
import logging
import argparse
from pathlib import Path
from typing import Tuple, Dict, Any

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)
from xgboost import XGBClassifier
import matplotlib.pyplot as plt
import seaborn as sns

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ThreatDetectionTrainer:
    """XGBoost model trainer for threat detection"""
    
    def __init__(self, model_dir: str = "ml-model/models"):
        """Initialize trainer"""
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = []

        encoder_path = self.model_dir / "label_encoder.pkl"
        if encoder_path.exists():
            with open(encoder_path, 'rb') as f:
                self.label_encoder = pickle.load(f)
        
    def load_data(self, data_path: str) -> pd.DataFrame:
        """Load and preprocess data"""
        logger.info(f"Loading data from {data_path}")
        
        if not os.path.exists(data_path):
            logger.error(f"Data file not found: {data_path}")
            raise FileNotFoundError(f"Data file not found: {data_path}")
        
        df = pd.read_csv(data_path)
        logger.info(f"Loaded {len(df)} records with {len(df.columns)} columns")
        
        return df
    
    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract features from raw data"""
        logger.info("Extracting features...")
        
        features = pd.DataFrame()
        
        # Network features
        if 'source.port' in df.columns:
            features['src_port_entropy'] = df['source.port'].apply(
                lambda x: self._calculate_entropy(str(x)) if pd.notna(x) else 0
            )
        
        if 'destination.port' in df.columns:
            features['dest_port_entropy'] = df['destination.port'].apply(
                lambda x: self._calculate_entropy(str(x)) if pd.notna(x) else 0
            )
        
        if 'network.bytes' in df.columns:
            features['bytes_sent_ratio'] = df['network.bytes'] / (df['network.bytes'].max() + 1)
        
        if 'network.packets' in df.columns:
            features['packet_size_mean'] = df['network.packets']
        
        # Authentication features
        if 'event.outcome' in df.columns:
            features['auth_failure'] = (df['event.outcome'] == 'failure').astype(int)
            features['auth_success'] = (df['event.outcome'] == 'success').astype(int)
        
        # Process features
        if 'process.pid' in df.columns:
            features['process_count'] = df.groupby('agent.hostname')['process.pid'].transform('count')
        
        if 'process.command_line' in df.columns:
            features['cmdline_length'] = df['process.command_line'].str.len().fillna(0)
            features['has_suspicious_cmd'] = df['process.command_line'].str.contains(
                'eval|exec|system|passthru|popen|proc_open|shell_exec|curl|wget',
                case=False, na=False
            ).astype(int)
        
        # Temporal features
        if '@timestamp' in df.columns:
            df['@timestamp'] = pd.to_datetime(df['@timestamp'])
            features['hour_of_day'] = df['@timestamp'].dt.hour
            features['day_of_week'] = df['@timestamp'].dt.dayofweek
            features['hour_sin'] = np.sin(2 * np.pi * features['hour_of_day'] / 24)
            features['hour_cos'] = np.cos(2 * np.pi * features['hour_of_day'] / 24)
        
        # MITRE features
        if 'mitre.technique_id' in df.columns:
            features['unique_mitre_techniques'] = df.groupby('agent.hostname')['mitre.technique_id'].transform('nunique')
            features['has_mitre'] = df['mitre.technique_id'].notna().astype(int)
        
        # Event type features
        if 'event.category' in df.columns:
            event_dummies = pd.get_dummies(df['event.category'], prefix='event_cat')
            features = pd.concat([features, event_dummies], axis=1)
        
        # Agent type features
        if 'agent.type' in df.columns:
            agent_dummies = pd.get_dummies(df['agent.type'], prefix='agent')
            features = pd.concat([features, agent_dummies], axis=1)
        
        # Fill NaN values
        features = features.fillna(0)
        
        # Store feature columns
        self.feature_columns = features.columns.tolist()
        
        logger.info(f"Extracted {len(self.feature_columns)} features")
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            probability = count / len(text)
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def prepare_data(self, df: pd.DataFrame, test_size: float = 0.2) -> Tuple:
        """Prepare data for training"""
        logger.info("Preparing data for training...")
        
        # Extract features
        X = self.extract_features(df)
        
        # Prepare labels
        if 'label' in df.columns:
            y = self.label_encoder.fit_transform(df['label'])
        elif 'detection.severity' in df.columns:
            y = (df['detection.severity'].isin(['critical', 'high'])).astype(int)
        else:
            logger.warning("No label column found, using synthetic labels")
            y = np.zeros(len(df))
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y if len(np.unique(y)) > 1 else None
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        logger.info(f"Training set: {len(X_train)} samples")
        logger.info(f"Test set: {len(X_test)} samples")
        logger.info(f"Label distribution: {dict(zip(*np.unique(y, return_counts=True)))}")
        
        return X_train_scaled, X_test_scaled, y_train, y_test
    
    def train_model(self, X_train: np.ndarray, y_train: np.ndarray, 
                    optimize: bool = False) -> XGBClassifier:
        """Train XGBoost model"""
        logger.info("Training XGBoost model...")
        
        # Base model
        model = XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            objective='binary:logistic',
            eval_metric='aucpr',
            scale_pos_weight=3,  # Handle class imbalance
            random_state=42,
            n_jobs=-1
        )
        
        if optimize:
            # Hyperparameter tuning
            param_grid = {
                'max_depth': [4, 6, 8],
                'learning_rate': [0.01, 0.1, 0.2],
                'n_estimators': [100, 200, 300]
            }
            
            grid_search = GridSearchCV(
                model, param_grid, cv=5, scoring='roc_auc', n_jobs=-1
            )
            grid_search.fit(X_train, y_train)
            
            model = grid_search.best_estimator_
            logger.info(f"Best parameters: {grid_search.best_params_}")
        else:
            model.fit(X_train, y_train)
        
        self.model = model
        
        logger.info("Model training completed")
        
        return model
    
    def evaluate_model(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Evaluate model performance"""
        logger.info("Evaluating model performance...")
        
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        # Make predictions
        y_pred = self.model.predict(X_test)
        y_prob = self.model.predict_proba(X_test)[:, 1]
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted'),
            'recall': recall_score(y_test, y_pred, average='weighted'),
            'f1': f1_score(y_test, y_pred, average='weighted'),
            'auc_roc': roc_auc_score(y_test, y_prob),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'classification_report': classification_report(y_test, y_pred, output_dict=True)
        }
        
        logger.info(f"Accuracy: {metrics['accuracy']:.4f}")
        logger.info(f"Precision: {metrics['precision']:.4f}")
        logger.info(f"Recall: {metrics['recall']:.4f}")
        logger.info(f"F1 Score: {metrics['f1']:.4f}")
        logger.info(f"AUC-ROC: {metrics['auc_roc']:.4f}")
        
        return metrics
    
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
    
    def plot_feature_importance(self, output_path: str, top_n: int = 20):
        """Plot feature importance"""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        # Get feature importance
        importance = self.model.feature_importances_
        feature_names = self.feature_columns[:len(importance)]
        
        # Create dataframe
        df_importance = pd.DataFrame({
            'feature': feature_names,
            'importance': importance
        }).sort_values('importance', ascending=False).head(top_n)
        
        # Plot
        plt.figure(figsize=(10, 8))
        sns.barplot(data=df_importance, x='importance', y='feature', palette='viridis')
        plt.title(f'Top {top_n} Feature Importance')
        plt.xlabel('Importance')
        plt.ylabel('Feature')
        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        plt.close()
        logger.info(f"Feature importance plot saved to {output_path}")
    
    def save_model(self):
        """Save model and preprocessing objects"""
        logger.info("Saving model and preprocessing objects...")
        
        # Save model
        model_path = self.model_dir / "xgboost_model.pkl"
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        logger.info(f"Model saved to {model_path}")
        
        # Save scaler
        scaler_path = self.model_dir / "feature_scaler.pkl"
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        logger.info(f"Scaler saved to {scaler_path}")
        
        # Save label encoder
        encoder_path = self.model_dir / "label_encoder.pkl"
        with open(encoder_path, 'wb') as f:
            pickle.dump(self.label_encoder, f)
        logger.info(f"Label encoder saved to {encoder_path}")
        
        # Save feature columns
        features_path = self.model_dir / "feature_columns.json"
        with open(features_path, 'w') as f:
            json.dump(self.feature_columns, f)
        logger.info(f"Feature columns saved to {features_path}")
    
    def train_pipeline(self, data_path: str, optimize: bool = False):
        """Complete training pipeline"""
        logger.info("Starting training pipeline...")
        
        # Load data
        df = self.load_data(data_path)
        
        # Prepare data
        X_train, X_test, y_train, y_test = self.prepare_data(df)
        
        # Train model
        self.train_model(X_train, y_train, optimize=optimize)
        
        # Evaluate model
        metrics = self.evaluate_model(X_test, y_test)
        
        # Plot results
        cm = np.array(metrics['confusion_matrix'])
        self.plot_confusion_matrix(cm, str(self.model_dir / "confusion_matrix.png"))
        self.plot_feature_importance(str(self.model_dir / "feature_importance.png"))
        
        # Save model
        self.save_model()
        
        # Save metrics
        metrics_path = self.model_dir / "training_metrics.json"
        with open(metrics_path, 'w') as f:
            json.dump(metrics, f, indent=2)
        logger.info(f"Metrics saved to {metrics_path}")
        
        logger.info("Training pipeline completed successfully")
        
        return metrics


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Train threat detection model')
    parser.add_argument('--data', required=True, help='Path to training data CSV')
    parser.add_argument('--model-dir', default='ml-model/models', help='Directory to save model')
    parser.add_argument('--optimize', action='store_true', help='Enable hyperparameter optimization')
    
    args = parser.parse_args()
    
    # Create trainer
    trainer = ThreatDetectionTrainer(model_dir=args.model_dir)
    
    # Run training pipeline
    try:
        metrics = trainer.train_pipeline(args.data, optimize=args.optimize)
        print("\n✅ Training completed successfully!")
        print(f"Accuracy: {metrics['accuracy']:.4f}")
        print(f"F1 Score: {metrics['f1']:.4f}")
        print(f"AUC-ROC: {metrics['auc_roc']:.4f}")
    except Exception as e:
        logger.error(f"Training failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()