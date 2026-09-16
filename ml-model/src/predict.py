#!/usr/bin/env python3
"""
predict.py
AI-Powered Threat Detection System
Real-time threat prediction using trained model
"""

import os
import sys
import json
import pickle
import logging
from pathlib import Path
from typing import Dict, Any, Optional

import numpy as np
import pandas as pd
from elasticsearch import Elasticsearch

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ThreatPredictor:
    """Real-time threat prediction using trained model"""
    
    def __init__(self, model_dir: str = "ml-model/models"):
        """Initialize predictor"""
        self.model_dir = Path(model_dir)
        
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_columns = []
        
        self._load_model()
    
    def _load_model(self):
        """Load trained model and preprocessing objects"""
        logger.info("Loading model and preprocessing objects...")
        
        # Load model
        model_path = self.model_dir / "xgboost_model.pkl"
        if model_path.exists():
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            logger.info(f"Model loaded from {model_path}")
        else:
            logger.warning(f"Model not found at {model_path}")
        
        # Load scaler
        scaler_path = self.model_dir / "feature_scaler.pkl"
        if scaler_path.exists():
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            logger.info(f"Scaler loaded from {scaler_path}")
        
        # Load label encoder
        encoder_path = self.model_dir / "label_encoder.pkl"
        if encoder_path.exists():
            with open(encoder_path, 'rb') as f:
                self.label_encoder = pickle.load(f)
            logger.info(f"Label encoder loaded from {encoder_path}")
        
        # Load feature columns
        features_path = self.model_dir / "feature_columns.json"
        if features_path.exists():
            with open(features_path, 'r') as f:
                self.feature_columns = json.load(f)
            logger.info(f"Feature columns loaded from {features_path}")
    
    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """Extract features from a single event"""
        features = {}
        
        # Network features
        if 'source' in event and 'port' in event['source']:
            features['src_port_entropy'] = self._calculate_entropy(str(event['source']['port']))
        
        if 'destination' in event and 'port' in event['destination']:
            features['dest_port_entropy'] = self._calculate_entropy(str(event['destination']['port']))
        
        if 'network' in event and 'bytes' in event['network']:
            features['bytes_sent_ratio'] = event['network']['bytes'] / (1000000 + 1)
        
        # Authentication features
        if 'event' in event:
            features['auth_failure'] = 1 if event['event'].get('outcome') == 'failure' else 0
            features['auth_success'] = 1 if event['event'].get('outcome') == 'success' else 0
        
        # Process features
        if 'process' in event:
            features['cmdline_length'] = len(event['process'].get('command_line', ''))
            features['has_suspicious_cmd'] = 1 if any(
                cmd in event['process'].get('command_line', '').lower()
                for cmd in ['eval', 'exec', 'system', 'passthru', 'curl', 'wget']
            ) else 0
        
        # Temporal features
        if '@timestamp' in event:
            from datetime import datetime
            try:
                ts = pd.to_datetime(event['@timestamp'])
                features['hour_of_day'] = ts.hour
                features['day_of_week'] = ts.dayofweek
                features['hour_sin'] = np.sin(2 * np.pi * ts.hour / 24)
                features['hour_cos'] = np.cos(2 * np.pi * ts.hour / 24)
            except:
                features['hour_of_day'] = 0
                features['day_of_week'] = 0
                features['hour_sin'] = 0
                features['hour_cos'] = 0
        
        # MITRE features
        if 'mitre' in event:
            features['has_mitre'] = 1
            features['unique_mitre_techniques'] = 1
        else:
            features['has_mitre'] = 0
            features['unique_mitre_techniques'] = 0
        
        # Create feature array
        feature_array = np.zeros(len(self.feature_columns))
        for i, col in enumerate(self.feature_columns):
            if col in features:
                feature_array[i] = features[col]
        
        return feature_array.reshape(1, -1)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            probability = count / len(text)
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def predict(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Predict if an event is malicious"""
        if self.model is None:
            raise ValueError("Model not loaded")
        
        # Extract features
        features = self.extract_features(event)
        
        # Scale features
        if self.scaler:
            features_scaled = self.scaler.transform(features)
        else:
            features_scaled = features
        
        # Make prediction
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0]
        
        # Get label
        if self.label_encoder:
            label = self.label_encoder.inverse_transform([prediction])[0]
        else:
            label = 'malicious' if prediction == 1 else 'benign'
        
        # Calculate severity score (0-100)
        severity_score = int(probability[1] * 100)
        
        # Determine severity level
        if severity_score >= 80:
            severity_level = 'critical'
        elif severity_score >= 60:
            severity_level = 'high'
        elif severity_score >= 40:
            severity_level = 'medium'
        elif severity_score >= 20:
            severity_level = 'low'
        else:
            severity_level = 'info'
        
        return {
            'prediction': label,
            'probability': float(probability[1]),
            'severity_score': severity_score,
            'severity_level': severity_level,
            'confidence': float(max(probability))
        }
    
    def predict_batch(self, events: list) -> list:
        """Predict for multiple events"""
        results = []
        for event in events:
            try:
                result = self.predict(event)
                results.append(result)
            except Exception as e:
                logger.error(f"Prediction failed for event: {str(e)}")
                results.append({
                    'prediction': 'error',
                    'probability': 0.0,
                    'severity_score': 0,
                    'severity_level': 'unknown',
                    'confidence': 0.0
                })
        return results


def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Predict threats using trained model')
    parser.add_argument('--model-dir', default='ml-model/models', help='Model directory')
    parser.add_argument('--event', type=str, help='JSON event to predict')
    parser.add_argument('--file', type=str, help='JSON file with events to predict')
    
    args = parser.parse_args()
    
    # Create predictor
    predictor = ThreatPredictor(model_dir=args.model_dir)
    
    if args.event:
        # Single event prediction
        try:
            event = json.loads(args.event)
            result = predictor.predict(event)
            print(json.dumps(result, indent=2))
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {str(e)}")
            sys.exit(1)
    
    elif args.file:
        # Batch prediction
        try:
            with open(args.file, 'r') as f:
                events = json.load(f)
            
            results = predictor.predict_batch(events)
            
            for i, result in enumerate(results):
                print(f"Event {i+1}: {json.dumps(result, indent=2)}")
        
        except Exception as e:
            logger.error(f"Batch prediction failed: {str(e)}")
            sys.exit(1)
    
    else:
        # Interactive mode
        print("Enter JSON events to predict (or 'quit' to exit):")
        while True:
            try:
                line = input("> ").strip()
                if line.lower() in ['quit', 'exit', 'q']:
                    break
                
                if line:
                    event = json.loads(line)
                    result = predictor.predict(event)
                    print(json.dumps(result, indent=2))
            
            except json.JSONDecodeError:
                print("Invalid JSON. Please enter a valid JSON object.")
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Prediction failed: {str(e)}")


if __name__ == "__main__":
    main()