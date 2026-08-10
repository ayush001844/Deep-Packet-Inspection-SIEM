from typing import Dict, Any

class FeatureExtractor:
    """
    Transforms raw network flow data from the SessionTracker into a structured feature vector
    suitable for Machine Learning analysis.
    """

    @staticmethod
    def extract_features(session_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Converts session dictionary into a numerical feature dictionary.
        """
        features = {}
        
        # 1. Packet Count
        features['packet_count'] = float(session_data.get('packets', 0))
        
        # 2. Total Bytes
        bytes_sent = session_data.get('bytes_sent', 0)
        bytes_recv = session_data.get('bytes_recv', 0)
        features['bytes'] = float(bytes_sent + bytes_recv)
        
        # 3. Duration
        duration = float(session_data.get('duration', 0.0))
        features['duration'] = duration
        
        # 4. Flow Rate (packets/sec)
        if duration > 0:
            features['flow_rate'] = features['packet_count'] / duration
        else:
            features['flow_rate'] = features['packet_count']
            
        # 5. Protocol (One-hot or numeric mapping)
        proto = session_data.get('proto', '').upper()
        features['is_tcp'] = 1.0 if proto == 'TCP' else 0.0
        features['is_udp'] = 1.0 if proto == 'UDP' else 0.0
        
        # 6. TCP Flags (Bitmask or counts)
        # Assuming the session_data['tcp_flags'] is a list of strings like ['SYN', 'ACK']
        flags = session_data.get('tcp_flags', [])
        syn_c = sum(1 for f in flags if 'SYN' in f)
        ack_c = sum(1 for f in flags if 'ACK' in f)
        fin_c = sum(1 for f in flags if 'FIN' in f)
        rst_c = sum(1 for f in flags if 'RST' in f)
        
        features['syn_count'] = float(syn_c)
        features['ack_count'] = float(ack_c)
        features['fin_count'] = float(fin_c)
        features['rst_count'] = float(rst_c)
        
        return features

    @staticmethod
    def get_feature_names() -> list[str]:
        return [
            'packet_count', 'bytes', 'duration', 'flow_rate',
            'is_tcp', 'is_udp', 'syn_count', 'ack_count', 'fin_count', 'rst_count'
        ]
