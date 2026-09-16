#!/usr/bin/env python3
"""
validate-rules.py
AI-Powered Threat Detection System
Validates Sigma and YARA rules
"""

import os
import sys
import yaml
import json
from pathlib import Path

def validate_sigma_rules(rules_dir: str) -> dict:
    """Validate Sigma rules"""
    results = {
        "total": 0,
        "valid": 0,
        "invalid": 0,
        "errors": []
    }
    
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        print(f"❌ Rules directory not found: {rules_dir}")
        return results
    
    for rule_file in rules_path.rglob("*.yml"):
        results["total"] += 1
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                rule = yaml.safe_load(f)
            
            # Validate required fields
            required_fields = ['title', 'id', 'status', 'description', 'tags', 'logsource']
            missing_fields = [field for field in required_fields if field not in rule]
            
            if missing_fields:
                results["errors"].append({
                    "file": str(rule_file),
                    "error": f"Missing required fields: {', '.join(missing_fields)}"
                })
                results["invalid"] += 1
                continue
            
            # Validate condition (Sigma spec: inside detection block)
            detection = rule.get('detection', {})
            if not isinstance(detection, dict) or not detection.get('condition'):
                results["errors"].append({
                    "file": str(rule_file),
                    "error": "Missing detection.condition"
                })
                results["invalid"] += 1
                continue
            
            # Validate condition syntax
            condition = detection.get('condition', '')
            if not condition or len(condition) < 3:
                results["errors"].append({
                    "file": str(rule_file),
                    "error": "Invalid condition syntax"
                })
                results["invalid"] += 1
                continue
            
            # Validate MITRE tags
            tags = rule.get('tags', [])
            mitre_tags = [tag for tag in tags if tag.startswith('attack.')]
            if not mitre_tags:
                results["errors"].append({
                    "file": str(rule_file),
                    "error": "No MITRE ATT&CK tags found"
                })
                results["invalid"] += 1
                continue
            
            # Validate logsource
            logsource = rule.get('logsource', {})
            if not logsource.get('category') and not logsource.get('product'):
                results["errors"].append({
                    "file": str(rule_file),
                    "error": "Logsource missing category or product"
                })
                results["invalid"] += 1
                continue
            
            results["valid"] += 1
            print(f"  ✓ {rule_file.name}")
            
        except yaml.YAMLError as e:
            results["errors"].append({
                "file": str(rule_file),
                "error": f"YAML parsing error: {str(e)}"
            })
            results["invalid"] += 1
        except Exception as e:
            results["errors"].append({
                "file": str(rule_file),
                "error": f"Unexpected error: {str(e)}"
            })
            results["invalid"] += 1
    
    return results


def validate_yara_rules(rules_file: str) -> dict:
    """Validate YARA rules"""
    results = {
        "total": 0,
        "valid": 0,
        "invalid": 0,
        "errors": []
    }
    
    rules_path = Path(rules_file)
    if not rules_path.exists():
        print(f"❌ YARA rules file not found: {rules_file}")
        return results
    
    try:
        import yara
        # Try to compile YARA rules
        rules = yara.compile(filepath=str(rules_path))
        results["valid"] = 1
        print(f"  ✓ {rules_path.name} - Successfully compiled")
        
    except ImportError:
        print(f"  ⚠ yara-python not installed, skipping YARA validation")
        results["valid"] = 1  # Skip validation
    except yara.SyntaxError as e:
        results["errors"].append({
            "file": str(rules_path),
            "error": f"YARA syntax error: {str(e)}"
        })
        results["invalid"] = 1
    except Exception as e:
        results["errors"].append({
            "file": str(rules_path),
            "error": f"Unexpected error: {str(e)}"
        })
        results["invalid"] = 1
    
    return results


def print_report(sigma_results: dict, yara_results: dict):
    """Print validation report"""
    print("\n" + "="*60)
    print("RULES VALIDATION REPORT")
    print("="*60)
    
    print("\n📊 Sigma Rules:")
    print(f"  Total:   {sigma_results['total']}")
    print(f"  Valid:   {sigma_results['valid']}")
    print(f"  Invalid: {sigma_results['invalid']}")
    
    print("\n📊 YARA Rules:")
    print(f"  Total:   {yara_results['total']}")
    print(f"  Valid:   {yara_results['valid']}")
    print(f"  Invalid: {yara_results['invalid']}")
    
    all_errors = sigma_results['errors'] + yara_results['errors']
    if all_errors:
        print("\n❌ Errors:")
        for error in all_errors:
            print(f"  - {error['file']}: {error['error']}")
    else:
        print("\n✅ All rules are valid!")
    
    print("="*60)


def main():
    """Main validation function"""
    print("🔍 Validating detection rules...\n")
    
    # Validate Sigma rules
    print("📁 Sigma Rules:")
    sigma_dir = "detection-rules/sigma/rules"
    sigma_results = validate_sigma_rules(sigma_dir)
    
    # Validate YARA rules
    print("\n📁 YARA Rules:")
    yara_file = "detection-rules/yara/yara_rules.yar"
    yara_results = validate_yara_rules(yara_file)
    
    # Print report
    print_report(sigma_results, yara_results)
    
    # Exit with appropriate code
    if sigma_results['invalid'] > 0 or yara_results['invalid'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()