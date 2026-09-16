#!/usr/bin/env python3
"""
triage_engine.py
AI-Powered Threat Detection System
Alert triage engine for automated alert processing
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class Severity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class TriageResult:
    """Result of alert triage"""
    alert_id: str
    timestamp: str
    severity: str
    severity_score: int
    confidence: float
    mitre_tactic: Optional[str]
    mitre_technique: Optional[str]
    recommended_action: str
    is_false_positive: bool
    triage_notes: str


class AlertTriageEngine:
    """Main alert triage engine"""
    
    def __init__(self, config_path: str = "config/triage_config.json"):
        """Initialize triage engine"""
        self.config = self._load_config(config_path)
        self.false_positive_patterns = self._load_fp_patterns()
        self.enrichment_sources = self._load_enrichment_sources()
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load triage configuration"""
        config = {
            "ml_score_weight": 0.4,
            "sigma_score_weight": 0.3,
            "yara_score_weight": 0.2,
            "mitre_score_weight": 0.1,
            "severity_thresholds": {
                "critical": 80,
                "high": 60,
                "medium": 40,
                "low": 20,
                "info": 0
            },
            "false_positive_threshold": 0.3,
            "auto_ir_threshold": 80
        }
        
        if Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    config.update(json.load(f))
            except Exception as e:
                logger.warning(f"Failed to load config: {e}")
        
        return config
    
    def _load_fp_patterns(self) -> List[Dict[str, Any]]:
        """Load false positive patterns"""
        return [
            {
                "name": "Internal Scanner",
                "type": "ip_whitelist",
                "values": ["192.168.1.100", "10.0.0.50"],
                "severity_adjustment": -30
            },
            {
                "name": "Backup Job",
                "type": "process_whitelist",
                "values": ["backup.exe", "rsync", "tar"],
                "severity_adjustment": -20
            },
            {
                "name": "IT Admin",
                "type": "user_whitelist",
                "values": ["admin", "it_support", "helpdesk"],
                "severity_adjustment": -15
            },
            {
                "name": "Business Hours Auth",
                "type": "time_whitelist",
                "values": ["08:00-18:00"],
                "severity_adjustment": -10
            }
        ]
    
    def _load_enrichment_sources(self) -> Dict[str, Any]:
        """Load enrichment source configurations"""
        return {
            "ip_reputation": {
                "enabled": True,
                "api_url": "https://api.example.com/ip-reputation"
            },
            "asset_criticality": {
                "enabled": True,
                "critical_assets": ["domain_controller", "database", "file_server"]
            },
            "user_role": {
                "enabled": True,
                "admin_roles": ["domain_admin", "local_admin"]
            }
        }
    
    def triage_alert(self, alert: Dict[str, Any]) -> TriageResult:
        """Triage a single alert"""
        logger.info(f"Triaging alert: {alert.get('alert_id', 'unknown')}")
        
        # Extract alert components
        ml_score = alert.get('ml_score', 0)
        sigma_matches = alert.get('sigma_matches', [])
        yara_matches = alert.get('yara_matches', [])
        mitre_info = alert.get('mitre', {})
        
        # Calculate composite score
        severity_score = self._calculate_severity_score(
            ml_score, sigma_matches, yara_matches, mitre_info
        )
        
        # Check for false positives
        is_fp = self._check_false_positive(alert)
        
        # Adjust score if false positive
        if is_fp:
            severity_score = max(0, severity_score - 30)
        
        # Determine severity level
        severity = self._determine_severity(severity_score)
        
        # Determine recommended action
        recommended_action = self._determine_action(severity, is_fp)
        
        # Generate triage notes
        triage_notes = self._generate_triage_notes(
            alert, severity_score, is_fp, sigma_matches, yara_matches
        )
        
        return TriageResult(
            alert_id=alert.get('alert_id', 'unknown'),
            timestamp=datetime.now().isoformat(),
            severity=severity.value,
            severity_score=severity_score,
            confidence=alert.get('ml_confidence', 0.0),
            mitre_tactic=mitre_info.get('tactic'),
            mitre_technique=mitre_info.get('technique'),
            recommended_action=recommended_action,
            is_false_positive=is_fp,
            triage_notes=triage_notes
        )
    
    def _calculate_severity_score(
        self,
        ml_score: float,
        sigma_matches: List[Dict],
        yara_matches: List[Dict],
        mitre_info: Dict
    ) -> int:
        """Calculate composite severity score (0-100)"""
        
        # ML Score (0-40 points)
        ml_component = ml_score * self.config['ml_score_weight'] * 100
        
        # Sigma Score (0-30 points)
        sigma_component = 0
        if sigma_matches:
            severity_map = {'critical': 30, 'high': 25, 'medium': 15, 'low': 5}
            max_sigma = max(severity_map.get(m.get('severity', 'low'), 5) for m in sigma_matches)
            sigma_component = max_sigma * self.config['sigma_score_weight'] * 100 / 30
        
        # YARA Score (0-20 points)
        yara_component = 0
        if yara_matches:
            yara_component = 20 * self.config['yara_score_weight'] * 100 / 20
        
        # MITRE Score (0-10 points)
        mitre_component = 0
        if mitre_info:
            severity_map = {'critical': 10, 'high': 8, 'medium': 5, 'low': 2}
            mitre_component = severity_map.get(mitre_info.get('severity', 'low'), 2) * self.config['mitre_score_weight'] * 100 / 10
        
        # Calculate total score
        total_score = ml_component + sigma_component + yara_component + mitre_component
        
        return min(100, max(0, int(total_score)))
    
    def _check_false_positive(self, alert: Dict[str, Any]) -> bool:
        """Check if alert is likely a false positive"""
        for pattern in self.false_positive_patterns:
            if pattern['type'] == 'ip_whitelist':
                source_ip = alert.get('source', {}).get('ip', '')
                if source_ip in pattern['values']:
                    return True
            
            elif pattern['type'] == 'process_whitelist':
                process_name = alert.get('process', {}).get('name', '')
                if process_name in pattern['values']:
                    return True
            
            elif pattern['type'] == 'user_whitelist':
                user_name = alert.get('user', {}).get('name', '')
                if user_name in pattern['values']:
                    return True
        
        return False
    
    def _determine_severity(self, score: int) -> Severity:
        """Determine severity level from score"""
        thresholds = self.config['severity_thresholds']
        
        if score >= thresholds['critical']:
            return Severity.CRITICAL
        elif score >= thresholds['high']:
            return Severity.HIGH
        elif score >= thresholds['medium']:
            return Severity.MEDIUM
        elif score >= thresholds['low']:
            return Severity.LOW
        else:
            return Severity.INFO
    
    def _determine_action(self, severity: Severity, is_fp: bool) -> str:
        """Determine recommended action"""
        if is_fp:
            return "suppress"
        
        actions = {
            Severity.CRITICAL: "auto_ir_playbook",
            Severity.HIGH: "analyst_review_15min",
            Severity.MEDIUM: "analyst_review_1hour",
            Severity.LOW: "batch_review",
            Severity.INFO: "log_only"
        }
        
        return actions.get(severity, "log_only")
    
    def _generate_triage_notes(
        self,
        alert: Dict[str, Any],
        severity_score: int,
        is_fp: bool,
        sigma_matches: List[Dict],
        yara_matches: List[Dict]
    ) -> str:
        """Generate triage notes"""
        notes = []
        
        if is_fp:
            notes.append("Likely false positive based on whitelist matching")
        
        if sigma_matches:
            rule_names = [m.get('rule_name', 'unknown') for m in sigma_matches]
            notes.append(f"Sigma rules triggered: {', '.join(rule_names)}")
        
        if yara_matches:
            rule_names = [m.get('rule_name', 'unknown') for m in yara_matches]
            notes.append(f"YARA rules triggered: {', '.join(rule_names)}")
        
        if severity_score >= 80:
            notes.append("HIGH PRIORITY: Auto-IR playbook recommended")
        
        return "; ".join(notes) if notes else "No additional notes"


def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Alert triage engine')
    parser.add_argument('--config', default='config/triage_config.json', help='Config file')
    parser.add_argument('--alert', type=str, help='JSON alert to triage')
    parser.add_argument('--file', type=str, help='JSON file with alerts to triage')
    
    args = parser.parse_args()
    
    # Create triage engine
    engine = AlertTriageEngine(config_path=args.config)
    
    if args.alert:
        # Single alert triage
        try:
            alert = json.loads(args.alert)
            result = engine.triage_alert(alert)
            print(json.dumps(asdict(result), indent=2))
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {str(e)}")
            sys.exit(1)
    
    elif args.file:
        # Batch triage
        try:
            with open(args.file, 'r') as f:
                alerts = json.load(f)
            
            results = []
            for alert in alerts:
                result = engine.triage_alert(alert)
                results.append(asdict(result))
            
            print(json.dumps(results, indent=2))
        
        except Exception as e:
            logger.error(f"Batch triage failed: {str(e)}")
            sys.exit(1)
    
    else:
        # Interactive mode
        print("Enter JSON alerts to triage (or 'quit' to exit):")
        while True:
            try:
                line = input("> ").strip()
                if line.lower() in ['quit', 'exit', 'q']:
                    break
                
                if line:
                    alert = json.loads(line)
                    result = engine.triage_alert(alert)
                    print(json.dumps(asdict(result), indent=2))
            
            except json.JSONDecodeError:
                print("Invalid JSON. Please enter a valid JSON object.")
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Triage failed: {str(e)}")


if __name__ == "__main__":
    main()