import os
import json
import numpy as np
import pandas as pd
import magic
import joblib
from typing import Dict, List, Any
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class AdvancedHeuristicAnalyzer:
    def __init__(self, config: Dict):
        """
        Initialize Advanced Heuristic Analyzer with ML capabilities
        
        :param config: Configuration dictionary
        """
        self.config = config.get('heuristic_thresholds', {})
        
        # Load dangerous extensions
        self.dangerous_extensions = self._load_dangerous_extensions()
        
        # Load pre-trained anomaly detection model
        self.ml_model = self._load_or_train_model()
        
        # Feature extraction mappings
        self.feature_extractors = {
            'file_size': self._extract_file_size,
            'entropy': self._calculate_file_entropy,
            'executable_ratio': self._check_executable_ratio,
            'suspicious_strings': self._detect_suspicious_strings
        }
    
    def _load_or_train_model(self, model_path: str = './models/anomaly_detector.joblib'):
        """
        Load existing model or train a new one
        
        :param model_path: Path to saved model
        :return: Trained Isolation Forest model
        """
        try:
            # Try to load existing model
            return joblib.load(model_path)
        except (FileNotFoundError, Exception):
            # Train a new model if no existing model found
            return self._train_anomaly_detection_model()
    
    def _train_anomaly_detection_model(self, 
                                       training_data_path: str = './data/benign_file_features.csv'):
        """
        Train an Isolation Forest for anomaly detection
        
        :param training_data_path: Path to training data
        :return: Trained Isolation Forest model
        """
        try:
            # Load training data
            df = pd.read_csv(training_data_path)
            
            # Select relevant features
            features = ['file_size', 'entropy', 'executable_ratio', 'suspicious_string_count']
            X = df[features]
            
            # Scale features
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            
            # Train Isolation Forest
            clf = IsolationForest(
                contamination=0.1,  # Assume 10% of files might be malicious
                random_state=42
            )
            clf.fit(X_scaled)
            
            # Save model and scaler
            os.makedirs('./models', exist_ok=True)
            joblib.dump(clf, './models/anomaly_detector.joblib')
            joblib.dump(scaler, './models/feature_scaler.joblib')
            
            return clf
        except Exception as e:
            print(f"Model training failed: {e}")
            return None
    
    def _extract_features(self, file_path: str) -> Dict[str, float]:
        """
        Extract features for machine learning analysis
        
        :param file_path: Path to file
        :return: Dictionary of extracted features
        """
        features = {}
        for name, extractor in self.feature_extractors.items():
            try:
                features[name] = extractor(file_path)
            except Exception:
                features[name] = np.nan
        
        return features
    
    def _extract_file_size(self, file_path: str) -> float:
        """Extract normalized file size"""
        return os.path.getsize(file_path)
    
    def _calculate_file_entropy(self, file_path: str) -> float:
        """Calculate file entropy as a measure of randomness"""
        from scipy.stats import entropy
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Count byte frequencies
        byte_freq = np.array(np.unique(data, return_counts=True)[1])
        byte_prob = byte_freq / len(data)
        return entropy(byte_prob, base=2)
    
    def _check_executable_ratio(self, file_path: str) -> float:
        """
        Calculate ratio of executable-like bytes in the file
        
        :param file_path: Path to file
        :return: Executable byte ratio
        """
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Check for common executable patterns
        executable_patterns = [
            b'\x4D\x5A',  # DOS/Windows executable header
            b'\x7F\x45\x4C\x46',  # ELF header
            b'\xCF\xFA\xED\xFE'  # Mach-O header
        ]
        
        pattern_matches = sum(
            data.count(pattern) for pattern in executable_patterns
        )
        
        return pattern_matches / len(data)
    
    def _detect_suspicious_strings(self, file_path: str) -> int:
        """
        Detect number of suspicious strings in the file
        
        :param file_path: Path to file
        :return: Count of suspicious strings
        """
        suspicious_patterns = [
            'cmd.exe', 'powershell', 'wget', 'curl', 
            'whoami', 'netstat', 'ipconfig'
        ]
        
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
        
        return sum(
            content.lower().count(pattern.lower()) 
            for pattern in suspicious_patterns
        )
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Comprehensive file analysis with ML-enhanced heuristics
        
        :param file_path: Path to file
        :return: Dictionary of potential threats
        """
        threats = {}
        
        try:
            # Basic heuristic checks
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Extension check
            if file_ext in self.dangerous_extensions:
                threats['dangerous_extension'] = f'High-risk file extension: {file_ext}'
            
            # Size anomaly check
            if (file_size < self.config.get('suspicious_file_size_min', 0) or 
                file_size > self.config.get('suspicious_file_size_max', float('inf'))):
                threats['size_anomaly'] = f'Unusual file size: {file_size} bytes'
            
            # MIME type check
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)
            
            # Machine Learning Anomaly Detection
            features = self._extract_features(file_path)
            
            # Load scaler
            try:
                scaler = joblib.load('./models/feature_scaler.joblib')
                feature_vector = scaler.transform(
                    pd.DataFrame([features])
                )[0]
                
                # Predict anomaly
                if self.ml_model is not None:
                    ml_prediction = self.ml_model.predict([feature_vector])[0]
                    if ml_prediction == -1:  # Anomaly detected
                        threats['ml_anomaly'] = 'Potential malware detected by ML model'
                        threats['ml_features'] = features
            except Exception as e:
                print(f"ML analysis failed: {e}")
            
            return threats
        
        except Exception as e:
            return {'analysis_error': str(e)}
    
    def _load_dangerous_extensions(self, 
                                   path: str = './data/dangerous_extensions.csv') -> List[str]:
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
