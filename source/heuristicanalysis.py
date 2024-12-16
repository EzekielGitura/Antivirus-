import os
import magic
from typing import Dict, List

class HeuristicAnalyzer:
    def __init__(self, config: Dict):
        """
        Initialize Heuristic Analyzer with configuration
        
        :param config: Configuration dictionary from antivirus_config.yaml
        """
        self.config = config.get('heuristic_thresholds', {})
        
        # Load dangerous extensions
        self.dangerous_extensions = self._load_dangerous_extensions()
    
    def _load_dangerous_extensions(self, path: str = './data/dangerous_extensions.csv') -> List[str]:
        """
        Load list of dangerous file extensions
        
        :param path: Path to CSV file with dangerous extensions
        :return: List of dangerous extensions
        """
        try:
            with open(path, 'r') as f:
                return [line.strip().lower() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            return ['.exe', '.bat', '.cmd', '.com', '.scr']
    
    def analyze_file(self, file_path: str) -> Dict[str, str]:
        """
        Perform heuristic analysis on a file
        
        :param file_path: Path to the file
        :return: Dictionary of potential threats
        """
        threats = {}
        
        try:
            # Size check
            file_size = os.path.getsize(file_path)
            if (file_size < self.config.get('suspicious_file_size_min', 0) or 
                file_size > self.config.get('suspicious_file_size_max', float('inf'))):
                threats['size_anomaly'] = f'Unusual file size: {file_size} bytes'
            
            # Extension check
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in self.dangerous_extensions:
                threats['dangerous_extension'] = f'Suspicious file extension: {file_ext}'
            
            # MIME type check
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)
            
            # Add more heuristics based on MIME type
            if file_type.startswith('application/x-dosexec'):
                threats['executable_type'] = 'Potentially executable Windows binary'
            
            # Timestamp anomaly
            stat = os.stat(file_path)
            if stat.st_mtime == stat.st_ctime:
                threats['timestamp_anomaly'] = 'Possible newly created suspicious file'
        
        except (OSError, IOError) as e:
            threats['access_error'] = f'Unable to analyze file: {str(e)}'
        
        return threats
