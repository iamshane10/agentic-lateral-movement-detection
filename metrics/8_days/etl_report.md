# LANL Dataset ETL Performance Report

**Generated:** 2026-03-13T00:01:07.667595

**Processing Time:** 25m 3s

**Peak Memory Usage:** 6373 MB

## Dataset Statistics

### Node Counts

| Node Type | Count |
|-----------|-------|
| Computers | 17,666 |
| Users | 100,162 |

### Edge Counts

| Edge Type | Count |
|-----------|-------|

### Temporal Event Reduction

| Event Type | Original | Filtered | Reduction |
|------------|----------|----------|----------|
| Authentications | 1,051,430,459 | 147,052,681 | 86.01% |
| Process Events | 426,045,096 | 54,661,597 | 87.17% |
| **Total** | **1,477,475,555** | **201,714,278** | **86.35%** |

## Processing Steps

| Step | Duration (s) | Memory (MB) |
|------|--------------|-------------|
| Database Initialization | 0.018 | 45 |
| Loading Raw Data Views | 191.310 | 57 |
| Creating Node Tables | 678.164 | 85 |
| Filtering Temporal Events | 448.377 | 2843 |
| Exporting to CSV | 185.814 | 6373 |
