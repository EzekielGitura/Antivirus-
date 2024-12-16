import os
import json
import requests
import hashlib
from typing import Dict, List
from datetime import datetime, timedelta

class ComprehensiveSignatureManager:
    def __init__(self, 
                 signatures_path: str = './config/comprehensive_signatures.json',
                 update_interval: int = 24):
        """
        Initialize Signature Manager with enhanced capabilities
        
        :param signatures_path: Path to signature database
        :param update_interval: Hours between signature updates
        """
        self.signatures_path = signatures_path
        self.update_interval = update_interval
        
        # External threat intelligence sources
        self.threat_sources = [
            'https://raw.githubusercontent.com/ytisf/theZoo/master/malware/Signatures/signatures.json',
            'https://github.com/stamparm/maltrail/raw/master/trails/static/malware/generic.txt'
        ]
        
        # Load or initialize signatures
        self.signatures = self._load_signatures()
    
    def _load_signatures(self) -> Dict[str, Dict]:
        """
        Load existing signatures or create new database
        
        :return: Signature database
        """
        try:
            with open(self.signatures_path, 'r') as f:
                signatures = json.load(f)
                
            # Check if update is needed
            last_update = datetime.fromisoformat(signatures.get('last_update', 
                                                               datetime.min.isoformat()))
            if datetime.now() - last_update > timedelta(hours=self.update_interval):
                self._update_signatures()
            
            return signatures
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                'last_update': datetime.min.isoformat(),
                'malware_signatures': {},
                'threat_intelligence': {}
            }
    
    def _update_signatures(self):
        """
        Update signature database from multiple sources
        """
        # Existing signatures
        try:
            new_signatures = self.signatures.get('malware_signatures', {})
            
            # Fetch from external sources
            for source in self.threat_sources:
                try:
                    response = requests.get(source, timeout=10)
                    source_signatures = self._parse_signature_source(source, response.text)
                    new_signatures.update(source_signatures)
                except Exception as e:
                    print(f"Error fetching signatures from {source}: {e}")
            
            # Update signatures
            self.signatures['malware_signatures'] = new_signatures
            self.signatures['last_update'] = datetime.now().isoformat()
            
            # Save updated signatures
            with open(self.signatures_path, 'w') as f:
                json.dump(self.signatures, f, indent=4)
        
        except Exception as e:
            print(f"Signature update failed: {e}")
    
    def _parse_signature_source(self, source: str, content: str) -> Dict[str, Dict]:
        """
        Parse different signature source formats
        
        :param source: URL of signature source
        :param content: Raw content from source
        :return: Parsed signatures
        """
        signatures = {}
        
        # Different parsing based on source type
        if 'theZoo' in source:
            # JSON-based signature parsing
            try:
                data = json.loads(content)
                for entry in data:
                    if 'hash' in entry:
                        signatures[entry['hash']] = {
                            'family': entry.get('family', 'Unknown'),
                            'type': entry.get('type', 'Generic Malware')
                        }
            except Exception:
                pass
        
        elif 'maltrail' in source:
            # Simple text-based hash list
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    signatures[line] = {
                        'family': 'Generic Threat',
                        'source': source
                    }
        
        return signatures
    
    def is_known_malware(self, file_hash: str) -> Dict:
        """
        Check if file hash matches known malware signatures
        
        :param file_hash: File hash to check
        :return: Threat details or False
        """
        signatures = self.signatures.get('malware_signatures', {})
        return signatures.get(file_hash, False)
    
    def report_new_threat(self, file_hash: str, details: Dict):
        """
        Allow reporting of new threats to expand signature database
        
        :param file_hash: File hash
        :param details: Threat details
        """
        self.signatures['malware_signatures'][file_hash] = details
        
        # Optional: Persist new signatures
        with open(self.signatures_path, 'w') as f:
            json.dump(self.signatures, f, indent=4)
