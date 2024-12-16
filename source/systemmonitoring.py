import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from signature_manager import SignatureManager
from heuristic_analyzer import HeuristicAnalyzer
from file_scanner import FileScanner

class RealTimeMonitor(FileSystemEventHandler):
    def __init__(self, config, signature_manager, heuristic_analyzer):
        """
        Initialize Real-Time File System Monitor
        
        :param config: Configuration dictionary
        :param signature_manager: SignatureManager instance
        :param heuristic_analyzer: HeuristicAnalyzer instance
        """
        self.config = config
        self.signature_manager = signature_manager
        self.heuristic_analyzer = heuristic_analyzer
        self.file_scanner = FileScanner(config, signature_manager, heuristic_analyzer)
        
        # Setup logging
        logging.basicConfig(
            filename=os.path.join(
                config.get('log_directory', './logs'), 
                'realtime_monitor.log'
            ),
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def on_created(self, event):
        """
        Handle file creation events
        
        :param event: Watchdog file system event
        """
        if not event.is_directory:
            self._check_file(event.src_path)
    
    def on_modified(self, event):
        """
        Handle file modification events
        
        :param event: Watchdog file system event
        """
        if not event.is_directory:
            self._check_file(event.src_path)
    
    def _check_file(self, file_path):
        """
        Perform real-time scanning on a file
        
        :param file_path: Path to file
        """
        try:
            threats = self.file_scanner._scan_file(file_path)
            
            if threats:
                self.logger.warning(f"Threat detected in {file_path}: {threats}")
                
                # Optional quarantine
                if self.config.get('quarantine_directory'):
                    quarantine_path = os.path.join(
                        self.config['quarantine_directory'], 
                        os.path.basename(file_path)
                    )
                    os.rename(file_path, quarantine_path)
                    self.logger.info(f"Quarantined {file_path}")
        
        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {e}")

def start_realtime_monitoring(config, signature_manager, heuristic_analyzer):
    """
    Start real-time file system monitoring
    
    :param config: Configuration dictionary
    :param signature_manager: SignatureManager instance
    :param heuristic_analyzer: HeuristicAnalyzer instance
    """
    monitor = RealTimeMonitor(config, signature_manager, heuristic_analyzer)
    observer = Observer()
    
    # Monitor specified directories
    for directory in config.get('scan_directories', [os.path.expanduser('~')]):
        observer.schedule(monitor, directory, recursive=True)
    
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    
    observer.join()
