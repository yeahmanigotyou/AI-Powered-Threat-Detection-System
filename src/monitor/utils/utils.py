import logging
import os
from typing import Dict, Any
from datetime import datetime
from enum import Enum
import json
from pathlib import Path
import numpy as np
from src.monitor.scan_type import ScanType

def setup_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(f"logs/{name}.log")
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

def ensure_directory():
    directories = ['logs','data','models']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)

def save_json_data(data: Dict[str, Any], filename: str):
    file_path = Path(filename)    
    with open(file_path, 'w') as f:
        json.dump(data, f, cls = CustomEncoder, indent=4)
        
def load_json_data(filepath: str) -> Dict:
    with open(filepath, 'r') as f:
        return json.load(f)

def safe_int(value, default=0):
    """Safely convert a value to int, return default if None or conversion fails."""
    try:
        return int(value) if value is not None else default
    except (ValueError, TypeError):
        return default

def safe_float(value, default=0.0):
    """Safely convert a value to float, return default if None or conversion fails."""
    try:
        return float(value) if value is not None else default
    except (ValueError, TypeError):
        return default

def safe_str(value, default='unknown'):
    """Safely convert a value to string, return default if None."""
    return str(value) if value is not None else default


class CustomEncoder(json.JSONEncoder):
    
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, Enum):
            return obj.name
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return vars(obj)
        elif isinstance(obj, ScanType):
            return obj.value
        return super(CustomEncoder, self).default(obj)
