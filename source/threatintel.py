import os
import json
import requests
from typing import Dict, List, Any
from datetime import datetime, timedelta

class ThreatIntelligenceManager:
    def __init__(self, config: Dict):
        """
        Initialize Threat Intelligence Manager
        
        :param config: Configuration dictionary
        """
        self.config = config
        self.intelligence_sources = [
            # Public threat intelligence APIs
            {
                'name': 'AbuseIPDB',
                'url': 'https://api.abuseipdb.com/api/v2/check',
                'api_key': config.get('threat_apis', {}).get('abuseipdb_key', '')
            },
            {
                'name': 'VirusTotal',
                'url': 'https://www.virustotal.com/api/v3/files/',
                'api_key': config.get('threat_apis', {}).get('virustotal_key', '')
            }
        ]
        
        # Threat cache to prevent repeated API calls
        self.threat_cache_path = './cache/threat_intelligence.json'
        self.threat_cache = self._load_threat_cache()
    
    def _load_threat_cache(self) -> Dict:
        """
        Load existing threat intelligence cache
        
        :return: Cached threat intelligence
        """
        try:
            with open(self.threat_cache_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                'ip_reputations': {},
                'file_hashes': {},
                'last_updated': datetime.min.isoformat()
            }
    
    def _save_threat_cache(self):
        """Save updated threat intelligence cache"""
        os.makedirs(os.path.dirname(self.threat_cache_path), exist_ok=True)
        with open(self.threat_cache_path, 'w') as f:
            json.dump(self.threat_cache, f, indent=4)
    
    def check_file_reputation(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash against multiple threat intelligence sources
        
        :param file_hash: SHA-256 file hash
        :return: Threat intelligence results
        """
        # Check cache first
        cache_entry = self.threat_cache['file_hashes'].get(file_hash)
        if cache_entry:
            # Check cache freshness
            if (datetime.now() - datetime.fromisoformat(cache_entry['timestamp'])) < timedelta(days=1):
                return cache_entry['result']
        
        # Aggregate results from multiple sources
        threat_results = {}
        
        for source in self.intelligence_sources:
            if source['name'] == 'VirusTotal':
                result = self._check_virustotal(file_hash, source['api_key'])
            else:
                continue  # Add more sources as needed
            
            if result:
                threat_results[source['name']] = result
        
        # Cache results
        if threat_results:
            self.threat_cache['file_hashes'][file_hash] = {
                'timestamp': datetime.now().isoformat(),
                'result': threat_results
            }
            self._save_threat_cache()
        
        return threat_results
    
    def _check_virustotal(self, file_hash: str, api_key: str) -> Dict:
        """
        Check file hash on VirusTotal
        
        :param file_hash: File hash
        :param api_key: VirusTotal API key
        :return: Threat detection results
        """
        if not api_key:
            return {}
        
        headers = {
            'x-apikey': api_key,
            'Accept': 'application/json'
        }
        
        try:
            response = requests.get(
                f'https://www.virustotal.com/api/v3/files/{file_hash}', 
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract key threat information
                return {
                    'detected': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0,
                    'total_votes': data.get('data', {}).get('attributes', {}).get('total_votes', {}),
                    'reputation_score': data.get('data', {}).get('attributes', {}).get('reputation', 0)
                }
        except Exception:
            return {}
    
    def analyze_network_threat(self, ip_address: str) -> Dict[str, Any]:
        """
        Analyze IP address reputation
        
        :param ip_address: IP address to check
        :return: IP reputation information
        """
        # Check cache first
        cache_entry = self.threat_cache['ip_reputations'].get(ip_address)
        if cache_entry:
            # Check cache freshness
            if (datetime.now() - datetime.fromisoformat(cache_entry['timestamp'])) < timedelta(hours=1):
                return cache_entry['result']
        
        # Check AbuseIPDB
        headers = {
            'Key': self.config.get('threat_apis', {}).get('abuseipdb_key', ''),
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90
        }
        
        try:
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check', 
                headers=headers, 
                params=params
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                # Prepare threat analysis
                threat_info = {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'is_public': data.get('isPublic', False),
                    'is_threat': data.get('abuseConfidenceScore', 0) > 50
                }
                
                # Cache result
                self.threat_cache['ip_reputations'][ip_address] = {
                    'timestamp': datetime.now().isoformat(),
                    'result': threat_info
                }
                self._save_threat_cache()
                
                return threat_info
        except Exception:
            pass
        
        return {}
