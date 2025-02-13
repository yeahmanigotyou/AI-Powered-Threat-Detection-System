import logging
import os
from typing import Dict, Any
from datetime import datetime
import json
import numpy as np

def setup_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(f"logs/{name}.log")
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

def ensure_directories():
    directories = ['logs','data','models']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)

def save_json_data(data: Dict[str, Any], filename: str):
    timestamp = datetime.now().strftime('%Y.%m.%d_%H.%M.%S')
    full_filename = f'data/{filename}_{timestamp}.json'
    
    with open(full_filename, 'w') as f:
        json.dump(data, f, indent=4)
        
def load_json_data(filepath: str) -> Dict:
    with open(filepath, 'r') as f:
        return json.load(f)
    

class NumpyEncoder(json.JSONEncoder):
    
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NumpyEncoder, self).default(obj)
