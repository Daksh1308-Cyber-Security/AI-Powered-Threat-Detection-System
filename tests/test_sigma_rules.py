#!/usr/bin/env python3
"""
test_sigma_rules.py
AI-Powered Threat Detection System
Unit tests for Sigma rule validation
"""

import os
import sys
import unittest
import yaml
from pathlib import Path
from typing import Dict, Any, List


class TestSigmaRules(unittest.TestCase):
    """Test Sigma rules for correctness and completeness"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.rules_dir = Path("detection-rules/sigma/rules")
        self.required_fields = ['title', 'id', 'status', 'description', 'tags', 'logsource']
        self.valid_statuses = ['experimental', 'testing', 'stable', 'deprecated', 'experimental']
        self.valid_severities = ['critical', 'high', 'medium', 'low', 'informational']
    
    def test_rules_directory_exists(self):
        """Test that rules directory exists"""
        self.assertTrue(self.rules_dir.exists(), f"Rules directory not found: {self.rules_dir}")
    
    def test_rules_directory_not_empty(self):
        """Test that rules directory is not empty"""
        rule_files = list(self.rules_dir.rglob("*.yml"))
        self.assertGreater(len(rule_files), 0, "No Sigma rules found")
    
    def test_all_rules_have_required_fields(self):
        """Test that all rules have required fields"""
        rule_files = list(self.rules_dir.rglob("*.yml"))
        
        for rule_file in rule_files:
            with self.subTest(rule_file=str(rule_file)):
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                
                for field in self.required_fields:
                    self.assertIn(field, rule, f"Missing required field '{field}' in {rule_file}")
    
    def test_rule_ids_are_unique(self):
        """Test that rule IDs are unique"""
        rule_files = list(self.rules_dir.rglob("*.yml"))
        rule_ids = []
        
        for rule_file in rule_files:
            with open(rule_file, 'r', encoding='utf-8') as f:
                rule = yaml.safe_load(f)
                rule_ids.append(rule.get('id'))
        
        # Check for duplicates
        seen_ids = set()
        duplicate_ids = set()
        for rule_id in rule_ids:
            if rule_id in seen_ids:
                duplicate_ids.add(rule_id)
            seen_ids.add(rule_id)
        
        self.assertEqual(len(duplicate_ids), 0, f"Duplicate rule IDs found: {duplicate_ids}")
    
    def test_rules_have_mitre_tags(self):
        """Test that rules have MITRE ATT&CK tags"""
        rule_files = list(self.rules_dir.rglob("*.yml"))
        
        for rule_file in rule_files:
            with self.subTest(rule_file=str(rule_file)):
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                
                tags = rule.get('tags', [])
                mitre_tags = [tag for tag in tags if tag.startswith('attack.')]
                
                self.assertGreater(
                    len(mitre_tags), 0,
                    f"No MITRE ATT&CK tags found in {rule_file}"
                )
    
    def test_rules_have_valid_logsource(self):
        """Test that rules have valid logsource"""
        rule_files = list(self.rules_dir.rglob("*.yml"))
        
        for rule_file in rule_files:
            with self.subTest(rule_file=str(rule_file)):
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                
                logsource = rule.get('logsource', {})
                self.assertTrue(
                    logsource.get('category') or logsource.get('product'),
                    f"Logsource missing category or product in {rule_file}"
                )
    
    def test_rules_have_valid_condition(self):
        """Test that rules have valid condition"""
        rule_files = list(self.rules_dir.rglob("*.yml"))
        
        for rule_file in rule_files:
            with self.subTest(rule_file=str(rule_file)):
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                
                condition = rule.get('detection', {}).get('condition', '')
                self.assertTrue(
                    len(condition) >= 3,
                    f"Invalid condition in {rule_file}"
                )
    
    def test_rules_have_falsepositives(self):
        """Test that rules have falsepositives field"""
        rule_files = list(self.rules_dir.rglob("*.yml"))
        
        for rule_file in rule_files:
            with self.subTest(rule_file=str(rule_file)):
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                
                self.assertIn(
                    'falsepositives', rule,
                    f"Missing falsepositives field in {rule_file}"
                )
    
    def test_rules_have_level(self):
        """Test that rules have level field"""
        rule_files = list(self.rules_dir.rglob("*.yml"))
        
        for rule_file in rule_files:
            with self.subTest(rule_file=str(rule_file)):
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                
                self.assertIn(
                    'level', rule,
                    f"Missing level field in {rule_file}"
                )
    
    def test_rules_by_tactic(self):
        """Test that we have rules for all required tactics"""
        required_tactics = [
            "attack.reconnaissance",
            "attack.initial_access",
            "attack.execution",
            "attack.persistence",
            "attack.privilege_escalation",
            "attack.defense_evasion",
            "attack.credential_access",
            "attack.discovery",
            "attack.lateral_movement",
            "attack.collection",
            "attack.exfiltration",
            "attack.command_and_control",
            "attack.impact"
        ]
        
        rule_files = list(self.rules_dir.rglob("*.yml"))
        all_tags = set()
        
        for rule_file in rule_files:
            with open(rule_file, 'r', encoding='utf-8') as f:
                rule = yaml.safe_load(f)
                all_tags.update(rule.get('tags', []))
        
        for tactic in required_tactics:
            self.assertIn(
                tactic, all_tags,
                f"No rules found for MITRE tactic: {tactic}"
            )


class TestSigmaRuleStructure(unittest.TestCase):
    """Test Sigma rule structure and syntax"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.rules_dir = Path("detection-rules/sigma/rules")
    
    def test_rules_have_detection(self):
        """Test that rules have detection field"""
        rule_files = list(self.rules_dir.rglob("*.yml"))
        
        for rule_file in rule_files:
            with self.subTest(rule_file=str(rule_file)):
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                
                self.assertIn(
                    'detection', rule,
                    f"Missing detection field in {rule_file}"
                )
    
    def test_detection_has_condition(self):
        """Test that detection has condition"""
        rule_files = list(self.rules_dir.rglob("*.yml"))
        
        for rule_file in rule_files:
            with self.subTest(rule_file=str(rule_file)):
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                
                detection = rule.get('detection', {})
                self.assertIn(
                    'condition', detection,
                    f"Detection missing condition in {rule_file}"
                )


if __name__ == '__main__':
    unittest.main(verbosity=2)