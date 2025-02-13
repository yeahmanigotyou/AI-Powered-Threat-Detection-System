import pandas as pd
import os
from src.monitor.utils.utils import load_json_data
from sklearn.preprocessing import MinMaxScaler

data_directory = os.path.join(os.getcwd(), 'data')

all_data = []

for filename in os.listdir(data_directory):
    if filename.startswith('captured_packets_') and filename.endswith('.json'):
        filepath = os.path.join(data_directory, filename)
        data = load_json_data(filepath)
        if data:
            all_data.append(data)

df = pd.DataFrame(all_data)

scaler = MinMaxScaler()

columns_to_normalize = []