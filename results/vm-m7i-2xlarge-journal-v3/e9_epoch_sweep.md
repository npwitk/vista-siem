# Journal v3: epoch length sweep

Systems J2R, S; Delta_e in 300, 900, 3600 s. Synthetic: 5 test seeds, alert budget per hour held constant. Delay = first alert epoch - first attack epoch, in hours.

## Synthetic (E1 test streams): F1 / delay (h)

| System | Delta_e (s) | cred_access | exfil | multi_source | macro F1 |
|---|---|---|---|---|---|
| J2R | 300 | 0.65 / 1.40 | 0.46 / 0.25 | 0.08 / 0.33 | 0.40 |
| J2R | 900 | 0.80 / 1.66 | 0.61 / 0.10 | 0.40 / 0.50 | 0.60 |
| J2R | 3600 | 0.64 / 0.53 | 0.55 / 0.00 | 0.72 / 0.00 | 0.64 |
| S | 300 | 0.65 / 1.40 | 0.46 / 0.25 | 0.08 / 0.33 | 0.40 |
| S | 900 | 0.80 / 1.66 | 0.61 / 0.10 | 0.40 / 0.50 | 0.60 |
| S | 3600 | 0.64 / 0.53 | 0.55 / 0.00 | 0.72 / 0.00 | 0.64 |

Total time 86s
