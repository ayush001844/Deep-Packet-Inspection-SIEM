import numpy as np

def extract_features(flow) -> np.ndarray:
    """
    Extracts 20 features from a SessionFlow object to match the
    CICIDS2017 feature space for ML inference.
    
    Expected order:
    0: duration (s)
    1: protocol (TCP=6, UDP=17, ICMP=1)
    2: src_bytes
    3: dst_bytes
    4: total_packets
    5: flow_bytes_per_s
    6: flow_pkts_per_s
    7: avg_pkt_size
    8: std_pkt_size
    9: min_pkt_size
    10: max_pkt_size
    11: syn_count
    12: fin_count
    13: rst_count
    14: psh_count
    15: ack_count
    16: unique_dst_ports (approx based on flow structure)
    17: unique_src_ports (approx based on flow structure)
    18: fwd_iat_mean
    19: bwd_iat_mean
    """
    
    # Safely get flow properties
    duration = getattr(flow, 'duration', 0.1)
    if duration <= 0:
        duration = 0.1
        
    protocol = 6 # Default TCP
    proto_str = getattr(flow, 'protocol', '').upper()
    if proto_str == 'UDP': protocol = 17
    elif proto_str == 'ICMP': protocol = 1
    
    src_bytes = getattr(flow, 'total_bytes', 0) / 2 # Approx if undirected
    dst_bytes = getattr(flow, 'total_bytes', 0) / 2
    
    total_packets = getattr(flow, 'packet_count', 1)
    
    flow_bytes_per_s = (src_bytes + dst_bytes) / duration
    flow_pkts_per_s = total_packets / duration
    
    # We might not have packet level size arrays in the flow object by default.
    # We will approximate them if missing, or use them if we add them to the flow model.
    packet_sizes = getattr(flow, 'packet_sizes', [])
    if packet_sizes:
        avg_pkt_size = np.mean(packet_sizes)
        std_pkt_size = np.std(packet_sizes)
        min_pkt_size = np.min(packet_sizes)
        max_pkt_size = np.max(packet_sizes)
    else:
        avg_pkt_size = (src_bytes + dst_bytes) / total_packets if total_packets > 0 else 0
        std_pkt_size = avg_pkt_size * 0.2
        min_pkt_size = avg_pkt_size * 0.5
        max_pkt_size = avg_pkt_size * 1.5
        
    flags = getattr(flow, 'tcp_flags', set())
    syn_count = getattr(flow, 'syn_count', 1 if 'S' in flags else 0)
    fin_count = getattr(flow, 'fin_count', 1 if 'F' in flags else 0)
    rst_count = getattr(flow, 'rst_count', 1 if 'R' in flags else 0)
    psh_count = getattr(flow, 'psh_count', 1 if 'P' in flags else 0)
    ack_count = getattr(flow, 'ack_count', 1 if 'A' in flags else 0)
    
    unique_dst_ports = 1
    unique_src_ports = 1
    
    iats = getattr(flow, 'inter_arrival_times', [])
    if iats:
        fwd_iat_mean = np.mean(iats)
        bwd_iat_mean = np.mean(iats)
    else:
        fwd_iat_mean = duration / total_packets if total_packets > 1 else duration
        bwd_iat_mean = fwd_iat_mean
        
    features = [
        duration, protocol, src_bytes, dst_bytes, total_packets,
        flow_bytes_per_s, flow_pkts_per_s, avg_pkt_size, std_pkt_size,
        min_pkt_size, max_pkt_size, syn_count, fin_count, rst_count,
        psh_count, ack_count, unique_dst_ports, unique_src_ports,
        fwd_iat_mean, bwd_iat_mean
    ]
    
    # Replace NaNs or Infs
    features = np.array(features, dtype=np.float32)
    features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
    
    return features
