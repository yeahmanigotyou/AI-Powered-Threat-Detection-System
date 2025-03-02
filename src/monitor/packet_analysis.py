# packet_analyzer.py
import numpy as np
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.ensemble import IsolationForest
from typing import List, Dict, Any
from src.monitor.utils.utils import setup_logger

class PacketAnalyzer:
    def __init__(self):
        self.logger = setup_logger("PacketAnalyzer")
        self.scaler = MinMaxScaler()
        self.protocol_encoder = LabelEncoder()
        self.protocol_list_encoder = LabelEncoder()  # For individual protocols in protocols list
        self.fitted = False

    def normalize_packets(self, packets: List[Dict[str, Any]]) -> np.ndarray:
        """Normalize packet data for AI analysis"""
        if not packets:
            self.logger.warning("No packets provided for normalization")
            return np.array([])

        # Extract features
        features = []
        for packet in packets:
            feature_vector = self._extract_features(packet)
            features.append(feature_vector)

        # Convert to numpy array
        feature_matrix = np.array(features, dtype=object)

        # Separate numerical and categorical features
        numerical_features = feature_matrix[:, :4].astype(float)  # timestamp, length, size, time_delta
        categorical_features = feature_matrix[:, 4:]  # protocol, protocols

        # Normalize numerical features
        if not self.fitted:
            self.scaler.fit(numerical_features)
            self.fitted = True
        normalized_numerical = self.scaler.transform(numerical_features)

        # Encode categorical features
        protocol_encoded = self._encode_protocols(categorical_features[:, 0])
        protocols_encoded = self._encode_protocol_list(categorical_features[:, 1])

        # Combine normalized features
        normalized_data = np.hstack((
            normalized_numerical,
            protocol_encoded.reshape(-1, 1),
            protocols_encoded
        ))

        self.logger.info(f"Normalized {len(packets)} packets into shape: {normalized_data.shape}")
        return normalized_data

    def _extract_features(self, packet: Dict[str, Any]) -> List[Any]:
        """Extract features from a single packet"""
        data = packet.get("data", {})
        metadata = packet.get("metadata", {})
        frame_info = data.get("metadata", {}).get("frame_info", {})

        # Numerical features
        timestamp = data.get("timestamp", 0.0)
        length = data.get("length", 0)
        size = metadata.get("size", 0)
        time_delta = frame_info.get("time_delta", 0.0)

        # Categorical features
        protocol = data.get("protocol", "unknown")
        protocols = frame_info.get("protocols", [])

        return [timestamp, length, size, time_delta, protocol, protocols]

    def _encode_protocols(self, protocols: np.ndarray) -> np.ndarray:
        """Encode protocol strings"""
        if not self.protocol_encoder.classes_.size:
            self.protocol_encoder.fit(protocols)
        return self.protocol_encoder.transform(protocols)

    def _encode_protocol_list(self, protocol_lists: np.ndarray) -> np.ndarray:
        """Encode list of protocols into binary presence vectors"""
        # Flatten all protocols into a unique set
        all_protocols = set()
        for plist in protocol_lists:
            all_protocols.update(plist)
        all_protocols = list(all_protocols)

        if not self.protocol_list_encoder.classes_.size:
            self.protocol_list_encoder.fit(all_protocols)

        # Create binary encoding for each packet's protocol list
        encoded = np.zeros((len(protocol_lists), len(all_protocols)))
        for i, plist in enumerate(protocol_lists):
            for proto in plist:
                if proto in all_protocols:
                    encoded[i, all_protocols.index(proto)] = 1
        return encoded
    
    def analyze_packets(self, packets: List[Dict[str, Any]], contamination: float = 0.1) -> List[Dict[str, Any]]:
        """Analyze packets with AI and return results"""
        normalized_data = self.normalize_packets(packets)
        if normalized_data.size == 0:
            return []

        # Train Isolation Forest for anomaly detection
        model = IsolationForest(contamination=contamination, random_state=42)
        predictions = model.fit_predict(normalized_data)

        # Add analysis results to original packets
        results = []
        for i, packet in enumerate(packets):
            is_anomaly = predictions[i] == -1  # -1 indicates anomaly, 1 is normal
            results.append({
                "original_packet": packet,
                "is_anomaly": is_anomaly,
                "normalized_features": normalized_data[i].tolist()
            })
            self.logger.info(f"Packet {i+1}: {'Anomaly' if is_anomaly else 'Normal'}")

        return results
