#!/usr/bin/env python3
"""
playbook_generator.py
AI-Powered Threat Detection System
Automated IR playbook generation
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, asdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class PlaybookAction:
    """Individual playbook action"""
    action_id: str
    name: str
    description: str
    command: str
    requires_approval: bool
    timeout_seconds: int
    rollback_command: Optional[str]


@dataclass
class IRPlaybook:
    """Incident Response Playbook"""
    playbook_id: str
    name: str
    description: str
    severity: str
    mitre_tactic: str
    mitre_technique: str
    created_at: str
    actions: List[PlaybookAction]
    estimated_duration: str
    required_roles: List[str]


class PlaybookGenerator:
    """Generate IR playbooks based on alert characteristics"""
    
    def __init__(self, templates_dir: str = "automation/ir-playbook/templates"):
        """Initialize playbook generator"""
        self.templates_dir = Path(templates_dir)
        self.templates = self._load_templates()
    
    def _load_templates(self) -> Dict[str, Any]:
        """Load playbook templates"""
        templates = {}
        
        if self.templates_dir.exists():
            for template_file in self.templates_dir.glob("*.json"):
                try:
                    with open(template_file, 'r') as f:
                        template = json.load(f)
                        templates[template['name']] = template
                except Exception as e:
                    logger.warning(f"Failed to load template {template_file}: {e}")
        
        # Default templates
        if not templates:
            templates = self._get_default_templates()
        
        return templates
    
    def _get_default_templates(self) -> Dict[str, Any]:
        """Get default playbook templates"""
        return {
            "ransomware": {
                "name": "Ransomware Response",
                "description": "Automated response to ransomware detection",
                "severity": "critical",
                "mitre_tactic": "impact",
                "mitre_technique": "T1486",
                "estimated_duration": "30-60 minutes",
                "required_roles": ["incident_responder", "security_analyst"],
                "actions": [
                    {
                        "action_id": "isolate_host",
                        "name": "Isolate Host",
                        "description": "Isolate the affected host from the network",
                        "command": "netsh advfirewall set allprofiles state off; New-NetFirewallRule -DisplayName 'Block All' -Direction Inbound -Action Block",
                        "requires_approval": True,
                        "timeout_seconds": 300,
                        "rollback_command": "netsh advfirewall set allprofiles state on"
                    },
                    {
                        "action_id": "disable_user",
                        "name": "Disable User Account",
                        "description": "Disable the compromised user account",
                        "command": "Disable-ADAccount -Identity {user_name}",
                        "requires_approval": True,
                        "timeout_seconds": 60,
                        "rollback_command": "Enable-ADAccount -Identity {user_name}"
                    },
                    {
                        "action_id": "collect_evidence",
                        "name": "Collect Evidence",
                        "description": "Collect forensic evidence from the host",
                        "command": "Get-Process | Export-Csv -Path 'C:\\forensics\\processes.csv'; Get-NetTCPConnection | Export-Csv -Path 'C:\\forensics\\network.csv'",
                        "requires_approval": False,
                        "timeout_seconds": 300,
                        "rollback_command": None
                    },
                    {
                        "action_id": "scan_system",
                        "name": "System Scan",
                        "description": "Run full system scan for malware",
                        "command": "Start-MpScan -ScanType FullScan",
                        "requires_approval": False,
                        "timeout_seconds": 3600,
                        "rollback_command": None
                    }
                ]
            },
            "data_exfiltration": {
                "name": "Data Exfiltration Response",
                "description": "Automated response to data exfiltration",
                "severity": "high",
                "mitre_tactic": "exfiltration",
                "mitre_technique": "T1048",
                "estimated_duration": "15-30 minutes",
                "required_roles": ["incident_responder", "security_analyst"],
                "actions": [
                    {
                        "action_id": "block_ip",
                        "name": "Block External IP",
                        "description": "Block the suspicious external IP",
                        "command": "New-NetFirewallRule -DisplayName 'Block Suspicious IP' -Direction Outbound -RemoteAddress {source_ip} -Action Block",
                        "requires_approval": True,
                        "timeout_seconds": 60,
                        "rollback_command": "Remove-NetFirewallRule -DisplayName 'Block Suspicious IP'"
                    },
                    {
                        "action_id": "capture_traffic",
                        "name": "Capture Network Traffic",
                        "description": "Start capturing network traffic for analysis",
                        "command": "netsh trace start capture=yes tracefile=C:\\forensics\\network_capture.etl",
                        "requires_approval": False,
                        "timeout_seconds": 300,
                        "rollback_command": "netsh trace stop"
                    },
                    {
                        "action_id": "check_dns",
                        "name": "Check DNS Queries",
                        "description": "Review recent DNS queries",
                        "command": "Get-DnsClientCache | Export-Csv -Path 'C:\\forensics\\dns_cache.csv'",
                        "requires_approval": False,
                        "timeout_seconds": 60,
                        "rollback_command": None
                    }
                ]
            },
            "credential_theft": {
                "name": "Credential Theft Response",
                "description": "Automated response to credential theft",
                "severity": "high",
                "mitre_tactic": "credential_access",
                "mitre_technique": "T1003",
                "estimated_duration": "20-45 minutes",
                "required_roles": ["incident_responder", "security_analyst", "domain_admin"],
                "actions": [
                    {
                        "action_id": "reset_password",
                        "name": "Reset User Password",
                        "description": "Force password reset for compromised account",
                        "command": "Set-ADAccountPassword -Identity {user_name} -Reset -NewPassword (ConvertTo-SecureString 'Temp@123' -AsPlainText -Force)",
                        "requires_approval": True,
                        "timeout_seconds": 60,
                        "rollback_command": None
                    },
                    {
                        "action_id": "revoke_tokens",
                        "name": "Revoke Authentication Tokens",
                        "description": "Revoke all authentication tokens",
                        "command": "Revoke-KerberosTicket -Identity {user_name}",
                        "requires_approval": True,
                        "timeout_seconds": 60,
                        "rollback_command": None
                    },
                    {
                        "action_id": "check_lateral",
                        "name": "Check Lateral Movement",
                        "description": "Check for lateral movement indicators",
                        "command": "Get-WinEvent -LogName Security -FilterXPath *[System[(EventID=4624 or EventID=4625)]] -MaxEvents 1000 | Export-Csv -Path 'C:\\forensics\\logon_events.csv'",
                        "requires_approval": False,
                        "timeout_seconds": 300,
                        "rollback_command": None
                    }
                ]
            }
        }
    
    def generate_playbook(self, alert: Dict[str, Any]) -> IRPlaybook:
        """Generate IR playbook based on alert"""
        logger.info(f"Generating playbook for alert: {alert.get('alert_id', 'unknown')}")
        
        # Determine playbook type based on MITRE technique
        mitre_technique = alert.get('mitre', {}).get('technique_id', '')
        severity = alert.get('severity', 'medium')
        
        # Select template
        template = self._select_template(mitre_technique, severity)
        
        # Generate playbook
        playbook = self._create_playbook(alert, template)
        
        return playbook
    
    def _select_template(self, mitre_technique: str, severity: str) -> Dict[str, Any]:
        """Select appropriate template based on MITRE technique"""
        # Prefer templates whose declared technique starts with the alert's ID.
        # Template files carry e.g. "T1486 - Data Encrypted for Impact".
        for template in self.templates.values():
            if mitre_technique and template.get('mitre_technique', '').startswith(mitre_technique):
                return template

        # Fall back to static slug mapping
        technique_mapping = {
            'T1486': 'ransomware',
            'T1048': 'data_exfiltration',
            'T1041': 'data_exfiltration',
            'T1567': 'data_exfiltration',
            'T1003': 'credential_theft',
            'T1110': 'credential_theft',
            'T1558': 'credential_theft',
            'T1021': 'lateral_movement',
            'T1570': 'lateral_movement'
        }
        
        template_name = technique_mapping.get(mitre_technique, 'default')
        
        if template_name in self.templates:
            return self.templates[template_name]
        
        # Default template
        return {
            "name": "Generic Incident Response",
            "description": "Generic IR playbook for security incidents",
            "severity": severity,
            "mitre_tactic": "unknown",
            "mitre_technique": mitre_technique,
            "estimated_duration": "15-30 minutes",
            "required_roles": ["incident_responder"],
            "actions": [
                {
                    "action_id": "investigate",
                    "name": "Investigate Alert",
                    "description": "Manually investigate the alert",
                    "command": "Write-Host 'Manual investigation required'",
                    "requires_approval": False,
                    "timeout_seconds": 300,
                    "rollback_command": None
                }
            ]
        }
    
    def _create_playbook(self, alert: Dict[str, Any], template: Dict[str, Any]) -> IRPlaybook:
        """Create IR playbook from template"""
        # Generate playbook ID
        playbook_id = f"PB-{datetime.now().strftime('%Y%m%d%H%M%S')}-{alert.get('alert_id', '000')[:8]}"
        
        # Create actions
        actions = []
        for action_data in template.get('actions', []):
            # Replace placeholders in commands
            command = action_data.get('command', '')
            command = command.replace('{source_ip}', alert.get('source', {}).get('ip', ''))
            command = command.replace('{user_name}', alert.get('user', {}).get('name', ''))
            command = command.replace('{destination_ip}', alert.get('destination', {}).get('ip', ''))
            
            action = PlaybookAction(
                action_id=action_data['action_id'],
                name=action_data['name'],
                description=action_data['description'],
                command=command,
                requires_approval=action_data.get('requires_approval', False),
                timeout_seconds=action_data.get('timeout_seconds', 300),
                rollback_command=action_data.get('rollback_command')
            )
            actions.append(action)
        
        return IRPlaybook(
            playbook_id=playbook_id,
            name=template['name'],
            description=template['description'],
            severity=template['severity'],
            mitre_tactic=template['mitre_tactic'],
            mitre_technique=template['mitre_technique'],
            created_at=datetime.now().isoformat(),
            actions=actions,
            estimated_duration=template['estimated_duration'],
            required_roles=template['required_roles']
        )
    
    def save_playbook(self, playbook: IRPlaybook, output_dir: str = "automation/ir-playbook/playbooks"):
        """Save playbook to file"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        playbook_file = output_path / f"{playbook.playbook_id}.json"
        
        with open(playbook_file, 'w') as f:
            json.dump(asdict(playbook), f, indent=2)
        
        logger.info(f"Playbook saved to {playbook_file}")
        
        return playbook_file


def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='IR Playbook Generator')
    parser.add_argument('--templates-dir', default='automation/ir-playbook/templates', help='Templates directory')
    parser.add_argument('--alert', type=str, help='JSON alert to generate playbook for')
    parser.add_argument('--output-dir', default='automation/ir-playbook/playbooks', help='Output directory')
    
    args = parser.parse_args()
    
    # Create generator
    generator = PlaybookGenerator(templates_dir=args.templates_dir)
    
    if args.alert:
        try:
            alert = json.loads(args.alert)
            playbook = generator.generate_playbook(alert)
            output_file = generator.save_playbook(playbook, args.output_dir)
            
            print(f"\n✅ Playbook generated: {playbook.playbook_id}")
            print(f"Name: {playbook.name}")
            print(f"Severity: {playbook.severity}")
            print(f"Actions: {len(playbook.actions)}")
            print(f"Saved to: {output_file}")
            
            # Print playbook details
            print("\n" + "="*60)
            print("PLAYBOOK DETAILS")
            print("="*60)
            print(f"\nDescription: {playbook.description}")
            print(f"MITRE: {playbook.mitre_tactic}/{playbook.mitre_technique}")
            print(f"Duration: {playbook.estimated_duration}")
            print(f"Required Roles: {', '.join(playbook.required_roles)}")
            
            print("\nActions:")
            for i, action in enumerate(playbook.actions, 1):
                approval = " (Requires Approval)" if action.requires_approval else ""
                print(f"  {i}. {action.name}{approval}")
                print(f"     {action.description}")
        
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {str(e)}")
            sys.exit(1)
    
    else:
        # Demo mode
        print("Playbook Generator - Demo Mode")
        print("Enter a JSON alert or 'quit' to exit:")
        
        while True:
            try:
                line = input("> ").strip()
                if line.lower() in ['quit', 'exit', 'q']:
                    break
                
                if line:
                    alert = json.loads(line)
                    playbook = generator.generate_playbook(alert)
                    
                    print(f"\nGenerated Playbook: {playbook.name}")
                    print(f"ID: {playbook.playbook_id}")
                    print(f"Actions: {len(playbook.actions)}")
            
            except json.JSONDecodeError:
                print("Invalid JSON. Please enter a valid JSON object.")
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Playbook generation failed: {str(e)}")


if __name__ == "__main__":
    main()