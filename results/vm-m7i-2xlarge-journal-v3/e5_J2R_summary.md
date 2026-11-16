# E5 results (synthetic data, variant J2R)

## Part A: manipulation detection

| Manipulation | Detected | Affected record decrypted | Clean run verified |
|---|---|---|---|
| modify payload ciphertext | 10/10 | 0/10 | 10/10 |
| modify HE feature | 10/10 | 0/10 | 10/10 |
| modify index entry | 10/10 | 0/10 | 10/10 |
| substitute record | 10/10 | 0/10 | 10/10 |
| reorder records | 10/10 | 0/10 | 10/10 |
| cross-epoch splice | 10/10 | 0/10 | 10/10 |
| rollback checkpoint (replay) | 10/10 | 0/10 | 10/10 |
| forge checkpoint root | 10/10 | 0/10 | 10/10 |
| truncate MMR size | 10/10 | 0/10 | 10/10 |
| forge MMR node | 10/10 | 0/10 | 10/10 |
| omit requested record | 10/10 | 0/10 | 10/10 |
| omit search result | 10/10 | 0/10 | 10/10 |
| replay stale index state | 10/10 | 0/10 | 10/10 |

Omitted search results: 10/10 detected by the authenticated EPII; plaintexts of the affected epochs withheld: 693.


## Part C: investigation latency (2048-bit keys)

| Attack | Window | Verified records | Plaintexts | Identity | Latency (ms) | EPII (ms) | Checkpoint (ms) | MMR (ms) | Bytes |
|---|---|---|---|---|---|---|---|---|---|
| multi_source | 2 | 19 | 19 | yes | 35.1 | 0.37 | 0.22 | 0.51 | 48,135 |
| multi_source | 2 | 19 | 19 | yes | 2.1 | 0.36 | 0.21 | 0.49 | 48,135 |
| multi_source | 2 | 19 | 19 | yes | 2.6 | 0.35 | 0.22 | 0.52 | 48,135 |
| multi_source | 2 | 19 | 19 | yes | 2.0 | 0.33 | 0.21 | 0.49 | 48,135 |
| multi_source | 2 | 19 | 19 | yes | 2.0 | 0.33 | 0.20 | 0.51 | 48,135 |
| multi_source | 2 | 19 | 19 | yes | 2.0 | 0.32 | 0.20 | 0.49 | 48,135 |
| multi_source | 2 | 19 | 19 | yes | 2.0 | 0.33 | 0.20 | 0.50 | 48,135 |
| multi_source | 2 | 19 | 19 | yes | 1.9 | 0.33 | 0.20 | 0.49 | 48,135 |
| multi_source | 2 | 19 | 19 | yes | 2.0 | 0.33 | 0.21 | 0.50 | 48,135 |
| multi_source | 2 | 19 | 19 | yes | 2.0 | 0.33 | 0.21 | 0.49 | 48,135 |
| multi_source | 2 | 26 | 8 | yes | 2.4 | 0.33 | 0.20 | 0.66 | 63,162 |
| multi_source | 2 | 26 | 8 | yes | 2.3 | 0.35 | 0.20 | 0.62 | 63,162 |
| multi_source | 2 | 26 | 8 | yes | 2.3 | 0.34 | 0.21 | 0.65 | 63,162 |
| multi_source | 2 | 26 | 8 | yes | 2.3 | 0.33 | 0.20 | 0.63 | 63,162 |
| multi_source | 2 | 26 | 8 | yes | 2.3 | 0.35 | 0.21 | 0.63 | 63,162 |
| multi_source | 2 | 26 | 8 | yes | 2.3 | 0.33 | 0.20 | 0.63 | 63,162 |
| multi_source | 2 | 26 | 8 | yes | 2.3 | 0.33 | 0.21 | 0.63 | 63,162 |
| multi_source | 2 | 26 | 8 | yes | 2.3 | 0.34 | 0.20 | 0.65 | 63,162 |
| multi_source | 2 | 26 | 8 | yes | 2.3 | 0.33 | 0.21 | 0.63 | 63,162 |
| multi_source | 2 | 26 | 8 | yes | 2.3 | 0.33 | 0.21 | 0.64 | 63,162 |
| cred_access | 3 | 136 | 60 | yes | 24.5 | 0.34 | 0.32 | 2.79 | 275,078 |
| cred_access | 3 | 136 | 60 | yes | 6.8 | 0.36 | 0.31 | 2.72 | 275,078 |
| cred_access | 3 | 136 | 60 | yes | 6.7 | 0.35 | 0.30 | 2.70 | 275,078 |
| cred_access | 3 | 136 | 60 | yes | 6.8 | 0.34 | 0.30 | 2.72 | 275,078 |
| cred_access | 3 | 136 | 60 | yes | 6.8 | 0.34 | 0.32 | 2.71 | 275,078 |
| cred_access | 3 | 136 | 60 | yes | 6.8 | 0.35 | 0.31 | 2.75 | 275,078 |
| cred_access | 3 | 136 | 60 | yes | 6.8 | 0.35 | 0.30 | 2.74 | 275,078 |
| cred_access | 3 | 136 | 60 | yes | 6.7 | 0.34 | 0.31 | 2.70 | 275,078 |
| cred_access | 3 | 136 | 60 | yes | 6.7 | 0.34 | 0.32 | 2.69 | 275,078 |
| cred_access | 3 | 136 | 60 | yes | 6.8 | 0.34 | 0.31 | 2.71 | 275,078 |
| multi_source | 3 | 26 | 26 | yes | 3.0 | 0.60 | 0.31 | 0.69 | 68,755 |
| multi_source | 3 | 26 | 26 | yes | 3.0 | 0.58 | 0.30 | 0.69 | 68,755 |
| multi_source | 3 | 26 | 26 | yes | 2.9 | 0.58 | 0.30 | 0.67 | 68,755 |
| multi_source | 3 | 26 | 26 | yes | 3.0 | 0.58 | 0.31 | 0.67 | 68,755 |
| multi_source | 3 | 26 | 26 | yes | 2.9 | 0.59 | 0.31 | 0.67 | 68,755 |
| multi_source | 3 | 26 | 26 | yes | 2.9 | 0.57 | 0.30 | 0.69 | 68,755 |
| multi_source | 3 | 26 | 26 | yes | 2.9 | 0.56 | 0.30 | 0.68 | 68,755 |
| multi_source | 3 | 26 | 26 | yes | 3.0 | 0.60 | 0.32 | 0.67 | 68,755 |
| multi_source | 3 | 26 | 26 | yes | 3.0 | 0.59 | 0.31 | 0.70 | 68,755 |
| multi_source | 3 | 26 | 26 | yes | 2.9 | 0.57 | 0.31 | 0.70 | 68,755 |
| multi_source | 3 | 147 | 65 | yes | 7.4 | 0.46 | 0.30 | 2.96 | 298,185 |
| multi_source | 3 | 147 | 65 | yes | 7.5 | 0.45 | 0.31 | 3.06 | 298,185 |
| multi_source | 3 | 147 | 65 | yes | 7.4 | 0.46 | 0.30 | 2.93 | 298,185 |
| multi_source | 3 | 147 | 65 | yes | 7.4 | 0.45 | 0.31 | 2.95 | 298,185 |
| multi_source | 3 | 147 | 65 | yes | 7.4 | 0.45 | 0.31 | 2.91 | 298,185 |
| multi_source | 3 | 147 | 65 | yes | 7.4 | 0.48 | 0.31 | 2.90 | 298,185 |
| multi_source | 3 | 147 | 65 | yes | 7.4 | 0.46 | 0.31 | 2.93 | 298,185 |
| multi_source | 3 | 147 | 65 | yes | 7.5 | 0.46 | 0.31 | 2.96 | 298,185 |
| multi_source | 3 | 147 | 65 | yes | 7.4 | 0.45 | 0.31 | 2.98 | 298,185 |
| multi_source | 3 | 147 | 65 | yes | 7.4 | 0.45 | 0.30 | 2.94 | 298,185 |
| multi_source | 4 | 37 | 37 | yes | 20.9 | 0.75 | 0.40 | 0.95 | 95,722 |
| multi_source | 4 | 37 | 37 | yes | 4.0 | 0.74 | 0.41 | 0.94 | 95,722 |
| multi_source | 4 | 37 | 37 | yes | 3.9 | 0.74 | 0.39 | 0.94 | 95,722 |
| multi_source | 4 | 37 | 37 | yes | 4.0 | 0.74 | 0.41 | 0.95 | 95,722 |
| multi_source | 4 | 37 | 37 | yes | 4.0 | 0.74 | 0.40 | 0.95 | 95,722 |
| multi_source | 4 | 37 | 37 | yes | 3.9 | 0.74 | 0.40 | 0.95 | 95,722 |
| multi_source | 4 | 37 | 37 | yes | 4.0 | 0.74 | 0.41 | 0.95 | 95,722 |
| multi_source | 4 | 37 | 37 | yes | 4.0 | 0.75 | 0.40 | 0.95 | 95,722 |
| multi_source | 4 | 37 | 37 | yes | 4.0 | 0.76 | 0.41 | 0.95 | 95,722 |
| multi_source | 4 | 37 | 37 | yes | 3.9 | 0.74 | 0.41 | 0.94 | 95,722 |
| cred_access | 5 | 137 | 61 | yes | 22.8 | 0.47 | 0.50 | 2.84 | 280,879 |
| cred_access | 5 | 137 | 61 | yes | 7.4 | 0.44 | 0.53 | 2.77 | 280,879 |
| cred_access | 5 | 137 | 61 | yes | 7.3 | 0.47 | 0.51 | 2.75 | 280,879 |
| cred_access | 5 | 137 | 61 | yes | 7.3 | 0.46 | 0.50 | 2.79 | 280,879 |
| cred_access | 5 | 137 | 61 | yes | 7.5 | 0.45 | 0.49 | 2.78 | 280,879 |
| cred_access | 5 | 137 | 61 | yes | 7.4 | 0.46 | 0.49 | 2.80 | 280,879 |
| cred_access | 5 | 137 | 61 | yes | 7.3 | 0.44 | 0.51 | 2.78 | 280,879 |
| cred_access | 5 | 137 | 61 | yes | 7.3 | 0.45 | 0.49 | 2.75 | 280,879 |
| cred_access | 5 | 137 | 61 | yes | 7.3 | 0.47 | 0.51 | 2.75 | 280,879 |
| cred_access | 5 | 137 | 61 | yes | 7.3 | 0.45 | 0.51 | 2.77 | 280,879 |
| exfil | 5 | 51 | 36 | yes | 4.3 | 0.37 | 0.49 | 1.33 | 119,157 |
| exfil | 5 | 51 | 36 | yes | 4.2 | 0.37 | 0.49 | 1.31 | 119,157 |
| exfil | 5 | 51 | 36 | yes | 4.2 | 0.36 | 0.49 | 1.31 | 119,157 |
| exfil | 5 | 51 | 36 | yes | 4.2 | 0.36 | 0.50 | 1.31 | 119,157 |
| exfil | 5 | 51 | 36 | yes | 4.2 | 0.36 | 0.50 | 1.34 | 119,157 |
| exfil | 5 | 51 | 36 | yes | 4.1 | 0.36 | 0.50 | 1.34 | 119,157 |
| exfil | 5 | 51 | 36 | yes | 4.1 | 0.36 | 0.49 | 1.34 | 119,157 |
| exfil | 5 | 51 | 36 | yes | 4.1 | 0.37 | 0.49 | 1.34 | 119,157 |
| exfil | 5 | 51 | 36 | yes | 4.2 | 0.38 | 0.49 | 1.33 | 119,157 |
| exfil | 5 | 51 | 36 | yes | 4.2 | 0.37 | 0.50 | 1.33 | 119,157 |
| multi_source | 5 | 41 | 41 | yes | 4.7 | 0.92 | 0.51 | 1.09 | 107,974 |
| multi_source | 5 | 41 | 41 | yes | 4.6 | 0.89 | 0.52 | 1.06 | 107,974 |
| multi_source | 5 | 41 | 41 | yes | 4.7 | 0.88 | 0.50 | 1.05 | 107,974 |
| multi_source | 5 | 41 | 41 | yes | 4.6 | 0.88 | 0.49 | 1.08 | 107,974 |
| multi_source | 5 | 41 | 41 | yes | 4.6 | 0.87 | 0.50 | 1.10 | 107,974 |
| multi_source | 5 | 41 | 41 | yes | 4.6 | 0.90 | 0.49 | 1.06 | 107,974 |
| multi_source | 5 | 41 | 41 | yes | 4.6 | 0.91 | 0.51 | 1.07 | 107,974 |
| multi_source | 5 | 41 | 41 | yes | 4.6 | 0.89 | 0.50 | 1.06 | 107,974 |
| multi_source | 5 | 41 | 41 | yes | 4.6 | 0.88 | 0.51 | 1.07 | 107,974 |
| multi_source | 5 | 41 | 41 | yes | 4.6 | 0.87 | 0.50 | 1.06 | 107,974 |
| cred_access | 6 | 138 | 60 | yes | 25.2 | 0.58 | 0.62 | 2.84 | 285,221 |
| cred_access | 6 | 138 | 60 | yes | 7.8 | 0.59 | 0.61 | 2.81 | 285,221 |
| cred_access | 6 | 138 | 60 | yes | 7.7 | 0.57 | 0.60 | 2.77 | 285,221 |
| cred_access | 6 | 138 | 60 | yes | 7.7 | 0.57 | 0.61 | 2.78 | 285,221 |
| cred_access | 6 | 138 | 60 | yes | 7.7 | 0.58 | 0.60 | 2.80 | 285,221 |
| cred_access | 6 | 138 | 60 | yes | 7.7 | 0.58 | 0.59 | 2.86 | 285,221 |
| cred_access | 6 | 138 | 60 | yes | 7.8 | 0.57 | 0.60 | 2.83 | 285,221 |
| cred_access | 6 | 138 | 60 | yes | 7.7 | 0.55 | 0.60 | 2.81 | 285,221 |
| cred_access | 6 | 138 | 60 | yes | 7.7 | 0.57 | 0.59 | 2.79 | 285,221 |
| cred_access | 6 | 138 | 60 | yes | 7.8 | 0.56 | 0.59 | 2.83 | 285,221 |

Part C spread over 100 investigations x repetitions (10 per investigation), ms: median / IQR / mean

| Quantity | median | IQR | mean |
|---|---|---|---|
| latency | 4.57 | 4.40 | 5.94 |
| epii | 0.46 | 0.23 | 0.51 |
| checkpoint | 0.36 | 0.20 | 0.38 |
| mmr | 1.21 | 2.09 | 1.64 |

Total time 90s
