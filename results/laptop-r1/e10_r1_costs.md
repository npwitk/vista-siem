# Journal r1: cost of the second-review fixes (2048-bit Paillier, seeds [1, 2, 3])

## Hunts: EE verification per hunt (median over hunts and seeds)

| Verify | f | Epoch | k | members checked | EE ms | EE HE adds | EE hashes | records fetched | all ok |
|---|---|---|---|---|---|---|---|---|---|
| real | 1.0 | current | 5 | 1 | 2.78 | 29 | 15 | 0 | True |
| real | 1.0 | historical | 5 | 1 | 3.27 | 32 | 132 | 16 | True |
| real | 0.1 | current | 5 | 1 | 2.71 | 0 | 15 | 0 | True |
| real | 0.1 | historical | 5 | 1 | 3.19 | 0 | 132 | 16 | True |
| all | 1.0 | current | 5 | 5 | 3.30 | 145 | 71 | 0 | True |
| all | 1.0 | historical | 5 | 5 | 5.66 | 160 | 668 | 80 | True |
| all | 0.1 | current | 5 | 5 | 2.84 | 0 | 71 | 0 | True |
| all | 0.1 | historical | 5 | 5 | 5.20 | 0 | 668 | 80 | True |

## Investigation per alert (median over alerts and seeds)

| Scope | alerts | window | queries | verified | decrypted | prov. by ref | kB cloud->SA | ms | failures |
|---|---|---|---|---|---|---|---|---|---|
| alerted entity only (v2/v3) | 32 | 3 | 3 | 44 | 44 | 0 total | 105.8 | 3.0 | 0 |
| whole group (r1) | 32 | 3 | 15 | 185 | 44 | 0 total | 393.5 | 6.7 | 0 |

Total time 65s
