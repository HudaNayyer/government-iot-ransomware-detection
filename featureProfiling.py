import pandas as pd
import numpy as np
from tqdm import tqdm
import os

# ------------------------------
# CONFIGURATION
# ------------------------------
DATA_FILE = "NF-ToN-IoT-v3.csv"
CHUNK_SIZE = 500_000

# Features to profile
FEATURES = [
    "OUT_PKTS","TCP_FLAGS","CLIENT_TCP_FLAGS","SERVER_TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS","DURATION_IN","DURATION_OUT",
    "MIN_TTL","MAX_TTL","LONGEST_FLOW_PKT","SHORTEST_FLOW_PKT",
    "MIN_IP_PKT_LEN","MAX_IP_PKT_LEN",
    "SRC_TO_DST_SECOND_BYTES","DST_TO_SRC_SECOND_BYTES",
    "RETRANSMITTED_IN_BYTES","RETRANSMITTED_IN_PKTS",
    "RETRANSMITTED_OUT_BYTES","RETRANSMITTED_OUT_PKTS",
    "SRC_TO_DST_AVG_THROUGHPUT","DST_TO_SRC_AVG_THROUGHPUT",
    "NUM_PKTS_UP_TO_128_BYTES","NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES","NUM_PKTS_512_TO_1024_BYTES",
    "NUM_PKTS_1024_TO_1514_BYTES",
    "TCP_WIN_MAX_IN","TCP_WIN_MAX_OUT",
    "ICMP_TYPE","ICMP_IPV4_TYPE",
    "DNS_QUERY_ID","DNS_QUERY_TYPE","DNS_TTL_ANSWER",
    "FTP_COMMAND_RET_CODE",
    "SRC_TO_DST_IAT_MIN","SRC_TO_DST_IAT_MAX","SRC_TO_DST_IAT_AVG","SRC_TO_DST_IAT_STDDEV",
    "DST_TO_SRC_IAT_MIN","DST_TO_SRC_IAT_MAX","DST_TO_SRC_IAT_AVG","DST_TO_SRC_IAT_STDDEV",
    "FLOW_START_MILLISECONDS","FLOW_END_MILLISECONDS",
    "IPV4_SRC_ADDR","L4_SRC_PORT","IPV4_DST_ADDR","L4_DST_PORT",
    "PROTOCOL","L7_PROTO",
    "IN_BYTES","IN_PKTS","OUT_BYTES",
    "Label","Attack"
]

# ------------------------------
# DETECT ACTUAL FEATURES
# ------------------------------
print("🔍 Detecting available features in dataset...")

sample = pd.read_csv(DATA_FILE, nrows=5)
ACTUAL_FEATURES = [f for f in FEATURES if f in sample.columns]

print(f"✅ Found {len(ACTUAL_FEATURES)} features")
print(f"📊 Dataset shape: {sample.shape}")

# ------------------------------
# ENHANCED STORAGE FOR RANSOMWARE COMPARISON
# ------------------------------
# Storage for all ransomware (for overall stats)
ransomware_stats = {f: {
    "count": 0, "mean": 0, "std": 0, "min": np.inf, "max": -np.inf, "null_count": 0
} for f in ACTUAL_FEATURES if f not in ["IPV4_SRC_ADDR", "IPV4_DST_ADDR", "Label", "Attack"]}

# Storage for coordinated ransomware (smart home - multiple targets from same source)
coordinated_ransomware_stats = {f: {
    "count": 0, "mean": 0, "std": 0, "min": np.inf, "max": -np.inf, "null_count": 0
} for f in ACTUAL_FEATURES if f not in ["IPV4_SRC_ADDR", "IPV4_DST_ADDR", "Label", "Attack"]}

# Storage for individual ransomware (single target attacks)
individual_ransomware_stats = {f: {
    "count": 0, "mean": 0, "std": 0, "min": np.inf, "max": -np.inf, "null_count": 0
} for f in ACTUAL_FEATURES if f not in ["IPV4_SRC_ADDR", "IPV4_DST_ADDR", "Label", "Attack"]}

# Coordination detection tracking
coordination_metrics = {
    "sources_with_multiple_targets": 0,
    "sources_with_single_target": 0,
    "total_ransomware_flows": 0,
    "coordinated_flows": 0,
    "individual_flows": 0
}

# For tracking source behavior across chunks
source_target_map = {}  # {source_ip: set(target_ips)}

# ------------------------------
# HELPER FUNCTIONS FOR COORDINATION ANALYSIS
# ------------------------------
def update_stats_incremental(existing_stats, new_data, col):
    """Update statistics incrementally for a feature"""
    if len(new_data) == 0:
        return existing_stats
    
    prev_count = existing_stats[col]["count"]
    new_count = prev_count + len(new_data)
    
    # Incremental mean update
    if prev_count > 0:
        existing_stats[col]["mean"] = (
            (existing_stats[col]["mean"] * prev_count + new_data.mean() * len(new_data)) 
            / new_count
        )
    else:
        existing_stats[col]["mean"] = new_data.mean()
    
    # Accumulate for variance
    existing_stats[col]["std"] += new_data.var() * len(new_data)
    
    existing_stats[col]["min"] = min(existing_stats[col]["min"], new_data.min())
    existing_stats[col]["max"] = max(existing_stats[col]["max"], new_data.max())
    existing_stats[col]["count"] = new_count
    
    return existing_stats

def detect_ransomware_coordination(chunk):
    """Identify coordinated vs individual ransomware based on source behavior"""
    ransomware_flows = chunk[
        (chunk['Label'] == 1) & 
        (chunk['Attack'].str.contains('ransomware', case=False, na=False))
    ]
    
    if len(ransomware_flows) == 0:
        return [], []
    
    coordinated_flows = []
    individual_flows = []
    
    # Analyze source behavior
    source_behavior = ransomware_flows.groupby('IPV4_SRC_ADDR').agg({
        'IPV4_DST_ADDR': 'nunique',
        'FLOW_DURATION_MILLISECONDS': 'mean',
        'IN_PKTS': 'sum'
    }).reset_index()
    
    # Update global source tracking
    for _, row in ransomware_flows.iterrows():
        src_ip = row['IPV4_SRC_ADDR']
        dst_ip = row['IPV4_DST_ADDR']
        
        if src_ip not in source_target_map:
            source_target_map[src_ip] = set()
        source_target_map[src_ip].add(dst_ip)
    
    # Classify flows based on source behavior
    for _, flow in ransomware_flows.iterrows():
        src_ip = flow['IPV4_SRC_ADDR']
        total_targets = len(source_target_map.get(src_ip, set()))
        
        if total_targets >= 2:  # Coordinated: attacking multiple targets
            coordinated_flows.append(flow)
        else:  # Individual: single target
            individual_flows.append(flow)
    
    return coordinated_flows, individual_flows

# ------------------------------
# PROCESSING LOOP WITH COORDINATION ANALYSIS
# ------------------------------
print(f"\n🔍 Starting enhanced profiling with coordination analysis...\n")

total_chunks = 0
total_rows = 0

for chunk in tqdm(pd.read_csv(DATA_FILE, chunksize=CHUNK_SIZE, low_memory=False), desc="Processing chunks"):
    total_chunks += 1
    chunk = chunk[ACTUAL_FEATURES]
    total_rows += len(chunk)
    
    # Detect ransomware coordination
    coordinated_flows, individual_flows = detect_ransomware_coordination(chunk)
    
    # Update coordination metrics
    coordination_metrics["total_ransomware_flows"] += len(coordinated_flows) + len(individual_flows)
    coordination_metrics["coordinated_flows"] += len(coordinated_flows)
    coordination_metrics["individual_flows"] += len(individual_flows)
    
    # Analyze ALL ransomware flows
    ransomware_mask = (chunk['Label'] == 1) & (chunk['Attack'].str.contains('ransomware', case=False, na=False))
    all_ransomware = chunk[ransomware_mask]
    
    numeric_features = [f for f in ransomware_stats.keys() if f in chunk.columns]
    
    # Update statistics for each category
    for col in numeric_features:
        # All ransomware
        ransom_data = all_ransomware[col].dropna()
        ransomware_stats = update_stats_incremental(ransomware_stats, ransom_data, col)
        
        # Coordinated ransomware
        if len(coordinated_flows) > 0:
            coord_df = pd.DataFrame(coordinated_flows)
            coord_data = coord_df[col].dropna() if col in coord_df.columns else pd.Series(dtype=float)
            coordinated_ransomware_stats = update_stats_incremental(coordinated_ransomware_stats, coord_data, col)
        
        # Individual ransomware
        if len(individual_flows) > 0:
            indiv_df = pd.DataFrame(individual_flows)
            indiv_data = indiv_df[col].dropna() if col in indiv_df.columns else pd.Series(dtype=float)
            individual_ransomware_stats = update_stats_incremental(individual_ransomware_stats, indiv_data, col)

print(f"\n✔ Processed {total_chunks} chunks, {total_rows:,} total rows")

# ------------------------------
# FINAL CALCULATIONS & COMPARISONS
# ------------------------------
print("\n📊 Calculating coordination differences...")

# Finalize standard deviations and create comparison
def finalize_stats(stats_dict):
    for col in stats_dict:
        if stats_dict[col]["count"] > 0:
            stats_dict[col]["std"] = np.sqrt(stats_dict[col]["std"] / stats_dict[col]["count"])
            # Round for readability
            for key in ['mean', 'std', 'min', 'max']:
                stats_dict[col][key] = round(stats_dict[col][key], 4)
    return stats_dict

ransomware_stats = finalize_stats(ransomware_stats)
coordinated_ransomware_stats = finalize_stats(coordinated_ransomware_stats)
individual_ransomware_stats = finalize_stats(individual_ransomware_stats)

# Calculate differences between coordinated and individual ransomware
coordination_differences = {}
for col in ransomware_stats.keys():
    if (coordinated_ransomware_stats[col]["count"] > 0 and 
        individual_ransomware_stats[col]["count"] > 0):
        
        coord_mean = coordinated_ransomware_stats[col]["mean"]
        indiv_mean = individual_ransomware_stats[col]["mean"]
        
        # Avoid division by zero
        if indiv_mean != 0:
            difference_ratio = coord_mean / indiv_mean
            absolute_diff = abs(coord_mean - indiv_mean)
        else:
            difference_ratio = float('inf')
            absolute_diff = abs(coord_mean)
        
        coordination_differences[col] = {
            'coordinated_mean': coord_mean,
            'individual_mean': indiv_mean,
            'difference_ratio': difference_ratio,
            'absolute_difference': absolute_diff,
            'coordinated_count': coordinated_ransomware_stats[col]["count"],
            'individual_count': individual_ransomware_stats[col]["count"]
        }

# ------------------------------
# SAVE ENHANCED RESULTS
# ------------------------------
os.makedirs("coordination_analysis", exist_ok=True)

# Save individual datasets
pd.DataFrame(ransomware_stats).T.to_csv("coordination_analysis/all_ransomware_stats.csv")
pd.DataFrame(coordinated_ransomware_stats).T.to_csv("coordination_analysis/coordinated_ransomware_stats.csv")
pd.DataFrame(individual_ransomware_stats).T.to_csv("coordination_analysis/individual_ransomware_stats.csv")

# Save coordination differences (most important file)
diff_df = pd.DataFrame(coordination_differences).T
diff_df = diff_df.sort_values('absolute_difference', ascending=False)
diff_df.to_csv("coordination_analysis/coordination_differences.csv")

# ------------------------------
# ENHANCED SUMMARY REPORT
# ------------------------------
print("\n" + "="*70)
print("COORDINATION ANALYSIS COMPLETED SUCCESSFULLY!")
print("="*70)

print(f"\n📊 Ransomware Distribution:")
print(f"   - Total ransomware flows: {coordination_metrics['total_ransomware_flows']:,}")
print(f"   - Coordinated (multi-target): {coordination_metrics['coordinated_flows']:,}")
print(f"   - Individual (single-target): {coordination_metrics['individual_flows']:,}")
print(f"   - Coordination ratio: {(coordination_metrics['coordinated_flows']/coordination_metrics['total_ransomware_flows'])*100:.1f}%")

print(f"\n🔍 Top 10 Features with Largest Coordination Differences:")
print("-" * 60)
top_differences = diff_df.head(10)
for feature, row in top_differences.iterrows():
    coord_mean = row['coordinated_mean']
    indiv_mean = row['individual_mean']
    ratio = row['difference_ratio']
    
    if ratio != float('inf'):
        print(f"   {feature:.<25} Coord: {coord_mean:>8.2f} | Indiv: {indiv_mean:>8.2f} | Ratio: {ratio:>6.2f}x")
    else:
        print(f"   {feature:.<25} Coord: {coord_mean:>8.2f} | Indiv: {indiv_mean:>8.2f} | Ratio: Infinite")

print(f"\n📁 Files saved to 'coordination_analysis/' folder:")
print(f"   - coordination_differences.csv (MAIN RESULTS)")
print(f"   - all_ransomware_stats.csv")
print(f"   - coordinated_ransomware_stats.csv") 
print(f"   - individual_ransomware_stats.csv")

print(f"\n🎉 Coordination analysis completed! Now you can see exactly how")
print("   coordinated ransomware differs from individual ransomware attacks.")