# Journal v3: EE ingest throughput (ip-172-31-8-110, Linux-7.0.0-1014-aws-x86_64-with-glibc2.39, 8 cores)

Paillier 2048 bits; 1500 synthetic events per worker (one epoch, its own EE shard and keys).

## A. Unit costs (median)

| Unit | µs |
|---|---|
| randomizer | 8,609.11 |
| enc_online | 3.11 |
| enc_full | 8,612.23 |
| aes_payload | 0.99 |
| prf | 1.38 |
| hash | 0.41 |

## B. Sustained ingest (real events per second, all workers)

| System | Mode | Workers | δ | HE enc / real event | events/s | events/s per worker | core-ms / real event |
|---|---|---|---|---|---|---|---|
| J2R | online | 1 | 0.70 | 5.11 | 8,952.4 | 8,952.4 | 0.11 |
| J2R | online | 2 | 0.67 | 5.00 | 17,967.4 | 8,983.7 | 0.11 |
| J2R | online | 4 | 0.64 | 4.93 | 36,037.9 | 9,009.5 | 0.11 |
| J2R | online | 8 | 0.65 | 4.94 | 36,207.8 | 4,526.0 | 0.21 |
| J2R | online+offline | 1 | 0.70 | 5.11 | 22.8 | 22.8 | 43.80 |
| J2R | online+offline | 2 | 0.67 | 5.00 | 45.5 | 22.7 | 42.94 |
| J2R | online+offline | 4 | 0.64 | 4.93 | 91.1 | 22.8 | 42.25 |
| J2R | online+offline | 8 | 0.65 | 4.94 | 99.7 | 12.5 | 79.14 |
| S | online | 1 | 0.00 | 3.00 | 14,532.0 | 14,532.0 | 0.07 |
| S | online | 2 | 0.00 | 3.00 | 28,986.1 | 14,493.1 | 0.07 |
| S | online | 4 | 0.00 | 3.00 | 57,820.9 | 14,455.2 | 0.07 |
| S | online | 8 | 0.00 | 3.00 | 59,004.7 | 7,375.6 | 0.13 |
| S | online+offline | 1 | 0.00 | 3.00 | 38.8 | 38.8 | 25.78 |
| S | online+offline | 2 | 0.00 | 3.00 | 77.6 | 38.8 | 25.69 |
| S | online+offline | 4 | 0.00 | 3.00 | 155.1 | 38.8 | 25.70 |
| S | online+offline | 8 | 0.00 | 3.00 | 164.3 | 20.5 | 48.62 |

## C. Per-real-event cost of the EE with offline work (one core) and cores for 10^4 events/s

| System | δ | HE enc / real | measured ms / real event (N = 1) | derived ms (enc x full enc + symmetric) | cores for 10^4 ev/s (online+offline) |
|---|---|---|---|---|---|
| J2R | 0.70 | 5.11 | 43.80 | 44.00 | 438 at the N = 1 rate, 802 at the N = 8 rate |
| S | 0.00 | 3.00 | 25.78 | 25.84 | 258 at the N = 1 rate, 487 at the N = 8 rate |

Derivation of the paper's figure: (HE encryptions per real event) x (full 2048-bit encryption) + symmetric work. Here a full encryption costs 8.61 ms (8.61 ms randomizer + 3.1 µs online) and the symmetric work 7.7 µs. D31 used 5.10 HE enc x 9.93 ms (m7i.2xlarge) = 50.7 ms. With the AIT-LDSv2 delta of J2R (1.69), 8.07 HE enc per real event give 69.5 ms on this machine (80.1 ms at the m7i unit cost).
Without offline work (randomizers precomputed on spare cores or ahead of time) the online part is 3.1 µs per encryption; see the online rows of Part B.

Total time 2045s
