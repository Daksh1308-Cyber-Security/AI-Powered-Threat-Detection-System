#!/usr/bin/env python3
"""
test_ml_model.py
AI-Powered Threat Detection System
Unit tests for ML model
"""

import os
import sys
import unittest
import json
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Any


class TestMLModel(unittest.TestCase):
    """Test ML model components"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.model_dir = Path("ml-model/models")
        self.model_file = self.model_dir / "xgboost_model.pkl"
        self.scaler_file = self.model_dir / "feature_scaler.pkl"
        self.encoder_file = self.model_dir / "label_encoder.pkl"
        self.features_file = self.model_dir / "feature_columns.json"
    
    def test_model_directory_exists(self):
        """Test that model directory exists"""
        self.assertTrue(self.model_dir.exists(), f"Model directory not found: {self.model_dir}")
    
    def test_model_file_exists(self):
        """Test that model file exists"""
        self.assertTrue(self.model_file.exists(), f"Model file not found: {self.model_file}")
    
    def test_scaler_file_exists(self):
        """Test that scaler file exists"""
        self.assertTrue(self.scaler_file.exists(), f"Scaler file not found: {self.scaler_file}")
    
    def test_encoder_file_exists(self):
        """Test that label encoder file exists"""
        self.assertTrue(self.encoder_file.exists(), f"Label encoder file not found: {self.encoder_file}")
    
    def test_features_file_exists(self):
        """Test that feature columns file exists"""
        self.assertTrue(self.features_file.exists(), f"Feature columns file not found: {self.features_file}")
    
    def test_model_loads(self):
        """Test that model loads successfully"""
        try:
            with open(self.model_file, 'rb') as f:
                model = pickle.load(f)
            self.assertIsNotNone(model, "Model failed to load")
        except Exception as e:
            self.fail(f"Model loading failed: {e}")
    
    def test_scaler_loads(self):
        """Test that scaler loads successfully"""
        try:
            with open(self.scaler_file, 'rb') as f:
                scaler = pickle.load(f)
            self.assertIsNotNone(scaler, "Scaler failed to load")
        except Exception as e:
            self.fail(f"Scaler loading failed: {e}")
    
    def test_encoder_loads(self):
        """Test that label encoder loads successfully"""
        try:
            with open(self.encoder_file, 'rb') as f:
                encoder = pickle.load(f)
            self.assertIsNotNone(encoder, "Label encoder failed to load")
        except Exception as e:
            self.fail(f"Label encoder loading failed: {e}")
    
    def test_features_loads(self):
        """Test that feature columns load successfully"""
        try:
            with open(self.features_file, 'r') as f:
                features = json.load(f)
            self.assertIsNotNone(features, "Feature columns failed to load")
            self.assertGreater(len(features), 0, "No features found")
        except Exception as e:
            self.fail(f"Feature columns loading failed: {e}")
    
    def test_model_predict(self):
        """Test that model can make predictions"""
        try:
            with open(self.model_file, 'rb') as f:
                model = pickle.load(f)
            
            # Create dummy input
            n_features = model.n_features_in_
            dummy_input = np.random.rand(1, n_features)
            
            # Make prediction
            prediction = model.predict(dummy_input)
            self.assertIsNotNone(prediction, "Prediction failed")
            self.assertEqual(len(prediction), 1, "Expected 1 prediction")
        except Exception as e:
            self.fail(f"Model prediction failed: {e}")
    
    def test_model_predict_proba(self):
        """Test that model can make probability predictions"""
        try:
            with open(self.model_file, 'rb') as f:
                model = pickle.load(f)
            
            # Create dummy input
            n_features = model.n_features_in_
            dummy_input = np.random.rand(1, n_features)
            
            # Make probability prediction
            probabilities = model.predict_proba(dummy_input)
            self.assertIsNotNone(probabilities, "Probability prediction failed")
            self.assertEqual(probabilities.shape[1], 2, "Expected 2 classes")
        except Exception as e:
            self.fail(f"Model probability prediction failed: {e}")
    
    def test_scaler_transform(self):
        """Test that scaler can transform data"""
        try:
            with open(self.scaler_file, 'rb') as f:
                scaler = pickle.load(f)
            
            # Create dummy input
            n_features = scaler.n_features_in_
            dummy_input = np.random.rand(1, n_features)
            
            # Transform data
            transformed = scaler.transform(dummy_input)
            self.assertIsNotNone(transformed, "Scaler transform failed")
        except Exception as e:
            self.fail(f"Scaler transform failed: {e}")
    
    def test_encoder_transform(self):
        """Test that label encoder can transform labels"""
        try:
            with open(self.encoder_file, 'rb') as f:
                encoder = pickle.load(f)
            
            # Get classes
            classes = encoder.classes_
            self.assertGreater(len(classes), 0, "No classes found")
            
            # Transform a label
            if len(classes) > 0:
                label = classes[0]
                transformed = encoder.transform([label])
                self.assertIsNotNone(transformed, "Encoder transform failed")
        except Exception as e:
            self.fail(f"Encoder transform failed: {e}")


class TestMLModelPerformance(unittest.TestCase):
    """Test ML model performance metrics"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.metrics_file = Path("ml-model/models/training_metrics.json")
    
    def test_metrics_file_exists(self):
        """Test that metrics file exists"""
        self.assertTrue(self.metrics_file.exists(), f"Metrics file not found: {self.metrics_file}")
    
    def test_metrics_have_required_fields(self):
        """Test that metrics have required fields"""
        required_fields = ['accuracy', 'precision', 'recall', 'f1', 'auc_roc']
        
        with open(self.metrics_file, 'r') as f:
            metrics = json.load(f)
        
        for field in required_fields:
            self.assertIn(field, metrics, f"Missing required field: {field}")
    
    def test_metrics_are_valid(self):
        """Test that metrics are valid (between 0 and 1)"""
        with open(self.metrics_file, 'r') as f:
            metrics = json.load(f)
        
        for field, value in metrics.items():
            if isinstance(value, (int, float)):
                self.assertGreaterEqual(value, 0, f"Metric {field} is negative")
                self.assertLessEqual(value, 1, f"Metric {field} is greater than 1")
    
    def test_model_meets_performance_thresholds(self):
        """Test that model meets minimum performance thresholds"""
        with open(self.metrics_file, 'r') as f:
            metrics = json.load(f)
        
        # Minimum thresholds
        thresholds = {
            'accuracy': 0.85,
            'precision': 0.85,
            'recall': 0.85,
            'f1': 0.85,
            'auc_roc': 0.90
        }
        
        for metric, threshold in thresholds.items():
            self.assertGreaterEqual(
                metrics.get(metric, 0),
                threshold,
                f"Model {metric} ({metrics.get(metric, 0):.4f}) below threshold ({threshold})"
            )


if __name__ == '__main__':
    unittest.main(verbosity=2)