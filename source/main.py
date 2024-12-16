import os
import sys
import yaml
import argparse

# Import local modules
from signature_manager import SignatureManager
from heuristic_analyzer import HeuristicAnalyzer
from file_scanner import FileScanner

def load_configuration(config_path: str = './config/antivirus_config.yaml') -> dict:
    """
    Load configuration from YAML file
    
    :param config_path: Path to configuration file
    :return: Configuration dictionary
    """
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Configuration file not found: {config_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing configuration: {e}")
        sys.exit(1)

def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description='Antivirus Prototype Scanner')
    parser.add_argument('-d', '--directories', 
                        nargs='+', 
                        help='Directories to scan (overrides config)')
    parser.add_argument('-v', '--verbose', 
                        action='store_true', 
                        help='Enable verbose output')
    args = parser.parse_args()

    # Load configuration
    config = load_configuration()

    # Override scan directories if provided via CLI
    if args.directories:
        config['scan_directories'] = args.directories

    # Initialize components
    signature_manager = SignatureManager()
    heuristic_analyzer = HeuristicAnalyzer(config)
    file_scanner = FileScanner(
        config, 
        signature_manager, 
        heuristic_analyzer
    )

    # Perform scan
    try:
        threats = file_scanner.scan_directories()
        
        # Optional quarantine of threats
        if threats and config.get('quarantine_directory'):
            print("\nQuarantining detected threats...")
            for file_path in threats.keys():
                try:
                    quarantine_path = os.path.join(
                        config['quarantine_directory'], 
                        os.path.basename(file_path)
                    )
                    os.rename(file_path, quarantine_path)
                    print(f"Moved {file_path} to quarantine")
                except Exception as e:
                    print(f"Could not quarantine {file_path}: {e}")
    
    except Exception as e:
        print(f"Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
