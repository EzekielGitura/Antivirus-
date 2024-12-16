import json
import os
import requests
from typing import Dict, List

class SignatureManager:
    def __init__(self, signatures_path: str = './config/local_signatures.json'):
        """
        Initialize Signature Manager with local signature database
        
        :param signatures_path: Path to local signatures JSON file
        """
        self.signatures_path = signatures_path
        self.signatures = self._load_signatures()
    
    def _load_signatures(self) -> Dict[str, Dict]:
        """
        Load signatures from local JSON file
        
        :return: Dictionary of signatures
        """
        try:
            with open(self.signatures_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Signature file not found: {self.signatures_path}")
            return {}
    
    def update_signatures(self, new_signatures: Dict[str, Dict]):
        """
        Update local signature database
        
        :param new_signatures: New signatures to add
        """
        self.signatures.update(new_signatures)
        with open(self.signatures_path, 'w') as f:
            json.dump(self.signatures, f, indent=4)
    
    def check_virustotal(self, file_hash: str, api_key: str) -> Dict:
        """
        Check file hash against VirusTotal database
        
        :param file_hash: SHA-256 hash of the file
        :param api_key: VirusTotal API key
        :return: VirusTotal scan results
        """
        if not api_key:
            return {"error": "No VirusTotal API key provided"}
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": api_key
        }
        
        try:
            response = requests.get(url, headers=headers)
            return response.json()
        except requests.RequestException as e:
            return {"error": f"VirusTotal API request failed: {str(e)}"}
    
    def is_known_malware(self, file_hash: str) -> bool:
        """
        Check if file hash matches known malware signatures
        
        :param file_hash: File hash to check
        :return: Boolean indicating if file is known malware
        """
        return file_hash in self.signatures
