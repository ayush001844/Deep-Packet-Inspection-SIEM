import numpy as np

def extract_features(flow) -> np.ndarray:
    """
    Extracts the 8 specific features for the ML model:
    0: duration (s)
    1: packet_count
    2: byte_count
    3: src_port
    4: dst_port
    5: protocol (TCP=6, UDP=17, ICMP=1, Other=0)
    6: flow_rate (bytes per second)
    7: tcp_flags (combined flag count or simple feature)
    """
    
    # 1. duration
    duration = getattr(flow, 'duration', 0.1)
    if duration <= 0:
        duration = 0.1
        
    # 2. packet_count
    packet_count = getattr(flow, 'total_packets', 1)
    
    # 3. byte_count
    byte_count = getattr(flow, 'total_bytes', 0)
    
    # 4. src_port
    src_port = getattr(flow, 'src_port', 0)
    
    # 5. dst_port
    dst_port = getattr(flow, 'dst_port', 0)
    
    # 6. protocol
    protocol = 6 # Default TCP
    proto_str = getattr(flow, 'protocol', '').upper()
    if proto_str == 'UDP': protocol = 17
    elif proto_str == 'ICMP': protocol = 1
    elif proto_str != 'TCP': protocol = 0
    
    # 7. flow_rate
    flow_rate = byte_count / duration
    
    # 8. tcp_flags
    flags = getattr(flow, 'tcp_flags', set())
    # A simple way to represent flags as a numerical feature: count of flags set
    tcp_flags = len(flags) if isinstance(flags, set) else 0

    features = [
        duration,
        packet_count,
        byte_count,
        src_port,
        dst_port,
        protocol,
        flow_rate,
        tcp_flags
    ]
    
    # Replace NaNs or Infs
    features = np.array(features, dtype=np.float32)
    features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
    
    return features
