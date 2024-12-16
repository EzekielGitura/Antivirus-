import os
import hashlib
import logging
import concurrent.futures
from typing import List, Dict, Tuple
from tqdm import tqdm

class FileScanner:
    def __init__(self, config: Dict, signature_manager, heuristic_analyzer):
        """
        Initialize File Scanner with configuration and supporting modules
        
        :param config: Configuration dictionary
        :param signature_manager: SignatureManager instance
        :param heuristic_analyzer: HeuristicAnalyzer instance
        """
        self.config = config
        self.signature_manager = signature_manager
        self.heuristic_analyzer = heuristic_analyzer
        
        # Setup logging
        logging.basicConfig(
            filename=os.path.join(config.get('log_directory', './logs'), 
                                  f'antivirus_scan_{os.getpid()}.log'),
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def _compute_file_hash(self, file_path: str, hash_algo: str = 'sha256') -> str:
        """
        Compute file hash
        
        :param file_path: Path to file
        :param hash_algo: Hashing algorithm (sha256 or md5)
        :return: Computed hash string
        """
        hash_func = hashlib.sha256() if hash_algo == 'sha256' else hashlib.md5()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except (IOError, OSError) as e:
            self.logger.error(f"Hash computation error for {file_path}: {e}")
            return ''
    
    def scan_directories(self, directories: List[str] = None) -> Dict[str, Dict]:
        """
        Scan specified directories for potential threats
        
        :param directories: List of directories to scan
        :return: Dictionary of detected threats
        """
        if not directories:
            directories = self.config.get('scan_directories', [os.path.expanduser('~')])
        
        threats = {}
        scanned_files = 0
        total_files = 0
        
        # Count total files first
        for directory in directories:
            for root, _, files in os.walk(directory):
                total_files += len(files)
        
        # Parallel scanning
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.get('max_threads', 4)
        ) as executor:
            # Progress bar
            pbar = tqdm(total=total_files, desc="Scanning Files", 
                        bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}')
            
            file_futures = {}
            for directory in directories:
                for root, _, files in os.walk(directory):
                    for filename in files:
                        file_path = os.path.join(root, filename)
                        
                        # Skip if not readable
                        if not os.access(file_path, os.R_OK):
                            continue
                        
                        future = executor.submit(self._scan_file, file_path)
                        file_futures[future] = file_path
            
            for future in concurrent.futures.as_completed(file_futures):
                file_path = file_futures[future]
                try:
                    file_threats = future.result()
                    if file_threats:
                        threats[file_path] = file_threats
                except Exception as e:
                    self.logger.error(f"Error scanning {file_path}: {e}")
                
                scanned_files += 1
                pbar.update(1)
            
            pbar.close()
        
        self._generate_report(threats, scanned_files, total_files)
        return threats
    
    def _scan_file(self, file_path: str) -> Dict[str, str]:
        """
        Perform comprehensive scan on a single file
        
        :param file_path: Path to file
        :return: Dictionary of detected threats
        """
        threats = {}
        
        # Compute file hash
        file_hash = self._compute_file_hash(file_path)
        if not file_hash:
            return threats
        
        # Signature matching
        if self.signature_manager.is_known_malware(file_hash):
            threats['signature_match'] = 'Known malware signature detected'
        
        # Heuristic analysis
        heuristic_results = self.heuristic_analyzer.analyze_file(file_path)
        if heuristic_results:
            threats.update(heuristic_results)
        
        # Optional VirusTotal check
        if self.config.get('virustotal', {}).get('enable_check'):
            vt_result = self.signature_manager.check_virustotal(
                file_hash, 
                self.config['virustotal'].get('api_key', '')
            )
            if vt_result.get('data', {}).get('attributes', {}).get('last_analysis_results'):
                threats['virustotal_detected'] = 'Potential threat detected by VirusTotal'
        
        return threats
    
    def _generate_report(self, threats: Dict, scanned_files: int, total_files: int):
        """
        Generate a comprehensive scan report
        
        :param threats: Detected threats
        :param scanned_files: Number of files scanned
        :param total_files: Total files in scan directories
        """
        report_path = os.path.join(
            self.config.get('log_directory', './logs'),
            f'antivirus_report_{os.getpid()}.txt'
        )
        
        with open(report_path, 'w') as report:
            report.write("=== Antivirus Scan Report ===\n")
            report.write(f"Total Files: {total_files}\n")
            report.write(f"Scanned Files: {scanned_files}\n")
            report.write(f"Threats Detected: {len(threats)}\n\n")
            
            if threats:
                report.write("Detected Threats:\n")
                for path, threat_details in threats.items():
                    report.write(f"\nFile: {path}\n")
                    for threat_type, description in threat_details.items():
                        report.write(f"  - {threat_type.upper()}: {description}\n")
        
        self.logger.info(f"Scan report generated: {report_path}")
        print(f"\nScan complete. Report saved to {report_path}")
