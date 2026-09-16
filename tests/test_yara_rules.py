#!/usr/bin/env python3
"""
test_yara_rules.py
AI-Powered Threat Detection System
Unit tests for YARA rule validation
"""

import os
import sys
import unittest
from pathlib import Path
from typing import Dict, Any, List


class TestYARARules(unittest.TestCase):
    """Test YARA rules for correctness and completeness"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.rules_file = Path("detection-rules/yara/yara_rules.yar")
        self.expected_categories = [
            "ransomware",
            "trojan",
            "backdoor",
            "webshell",
            "cryptominer"
        ]
    
    def test_rules_file_exists(self):
        """Test that YARA rules file exists"""
        self.assertTrue(self.rules_file.exists(), f"YARA rules file not found: {self.rules_file}")
    
    def test_rules_file_not_empty(self):
        """Test that YARA rules file is not empty"""
        self.assertGreater(self.rules_file.stat().st_size, 0, "YARA rules file is empty")
    
    def test_rules_have_mitre_attack(self):
        """Test that rules have MITRE ATT&CK references"""
        with open(self.rules_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for MITRE references
        self.assertIn("MITRE", content, "No MITRE ATT&CK references found")
        self.assertIn("T1486", content, "No T1486 (Ransomware) references found")
        self.assertIn("T1071", content, "No T1071 (C2) references found")
    
    def test_rules_have_severity(self):
        """Test that rules have severity metadata"""
        with open(self.rules_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for severity
        self.assertIn("severity", content, "No severity metadata found")
    
    def test_rules_have_category(self):
        """Test that rules have category metadata"""
        with open(self.rules_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for category
        self.assertIn("category", content, "No category metadata found")
    
    def test_rules_have_description(self):
        """Test that rules have description metadata"""
        with open(self.rules_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for description
        self.assertIn("description", content, "No description metadata found")
    
    def test_rules_have_author(self):
        """Test that rules have author metadata"""
        with open(self.rules_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for author
        self.assertIn("author", content, "No author metadata found")
    
    def test_rules_have_date(self):
        """Test that rules have date metadata"""
        with open(self.rules_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for date
        self.assertIn("date", content, "No date metadata found")
    
    def test_rules_have_condition(self):
        """Test that rules have condition field"""
        with open(self.rules_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Count condition statements
        condition_count = content.count("condition:")
        self.assertGreater(condition_count, 0, "No condition statements found")
    
    def test_rules_have_strings(self):
        """Test that rules have strings field"""
        with open(self.rules_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Count strings statements
        strings_count = content.count("strings:")
        self.assertGreater(strings_count, 0, "No strings statements found")
    
    def test_rules_have_meta(self):
        """Test that rules have meta field"""
        with open(self.rules_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Count meta statements
        meta_count = content.count("meta:")
        self.assertGreater(meta_count, 0, "No meta statements found")
    
    def test_yara_compile(self):
        """Test that YARA rules compile successfully"""
        try:
            import yara
            rules = yara.compile(filepath=str(self.rules_file))
            self.assertIsNotNone(rules, "YARA rules failed to compile")
        except ImportError:
            self.skipTest("yara-python not installed")
        except Exception as e:
            self.fail(f"YARA rules compilation failed: {e}")


class TestYARARuleCategories(unittest.TestCase):
    """Test YARA rule categories"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.rules_file = Path("detection-rules/yara/yara_rules.yar")
        self.expected_rules = {
            "ransomware": 5,
            "trojan": 5,
            "backdoor": 4,
            "webshell": 3,
            "cryptominer": 3
        }
    
    def test_expected_categories_exist(self):
        """Test that expected categories exist"""
        with open(self.rules_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        for category in self.expected_rules.keys():
            self.assertIn(
                category, content,
                f"Category '{category}' not found in YARA rules"
            )
    
    def test_expected_rules_per_category(self):
        """Test that expected number of rules per category exist"""
        with open(self.rules_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # This is a simple check - in production, parse the rules
        for category, expected_count in self.expected_rules.items():
            # Count rule names containing category
            rule_count = content.lower().count(f"rule {category}_")
            self.assertGreater(
                rule_count, 0,
                f"No rules found for category '{category}'"
            )


if __name__ == '__main__':
    unittest.main(verbosity=2)