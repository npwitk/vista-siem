# Journal v3: EE / cloud resource split (J2R, synthetic)

3 seed(s), 8 epochs x 1500 events, 200 users, Paillier 2048 bits, hunting workload on (e3_aqrs); decoys per real event 0.66. Mean per epoch; single-core wall seconds.

| Party | Component | s / epoch | ms / real event | share of party |
|---|---|---|---|---|
| EE | online | 0.127 | 0.083 | 0.2% |
| EE | offline | 65.085 | 42.627 | 99.7% |
| EE | index | 0.009 | 0.006 | 0.0% |
| EE | acl_verify | 0.033 | 0.022 | 0.1% |
| EE | graph_verify | 0.003 | 0.002 | 0.0% |
| EE | scoring | 0.008 | 0.005 | 0.0% |
| EE | **total** | **65.265** | **42.744** | |
| Cloud | store | 0.007 | 0.005 | 4.4% |
| Cloud | retrieve | 0.022 | 0.015 | 14.0% |
| Cloud | aggregate | 0.114 | 0.075 | 72.2% |
| Cloud | commit | 0.012 | 0.008 | 7.5% |
| Cloud | graph | 0.003 | 0.002 | 1.9% |
| Cloud | **total** | **0.158** | **0.103** | |

| Storage / memory | value |
|---|---|
| EE retained at epoch end (mean / max over epochs) | 4.64 / 4.84 MB |
| of which epoch HE ciphertexts (D23) | 3.91 MB |
| of which epoch index entries | 0.46 MB |
| of which trusted history state | 53.9 kB |
| Cloud stored, one epoch (mean) | 4.67 MB |
| Cloud stored, cumulative after 8 epochs | 37.36 MB |
| Process peak RSS (EE + cloud + KA in one process; upper bound) | 108 MB |

EE share of total compute: 99.8% (offline randomizers are 99.7% of the EE's time).

Total time 530s
