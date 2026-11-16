# VISTA-SIEM

Reference implementation and experiments for **VISTA-SIEM: Verifiable and Integrated Security Telemetry Analytics over Multi-Source Encrypted Logs** (submitted to *IEEE Transactions on Cloud Computing*).

VISTA-SIEM lets a cloud SIEM search, aggregate, and correlate multi-source logs it cannot read. A trusted on-premises Edge Encryptor (EE):
- verifies what the cloud computed before anything is released;
- hides which entity an analyst hunts, by issuing every hunt for the entity's whole volume-ranked group, padded to a common volume.

**Origin.** VISTA-SIEM is forked from **SIEMCrypt** (*Privacy-Preserving Security Event Analytics over Multi-Source Encrypted Log Data*), a research project at the Sirindhorn International Institute of Technology (SIIT), Thammasat University.
- This repository is a snapshot of that codebase, extended for the journal version.
- The package was renamed from `siemcrypt` to `vista_siem`.
- The development history is not included.
- Some configuration names and older result files keep SIEMCrypt-era labels (see below).

This repository contains the prototype (all six phases, with explicit parties and message passing), the experiment scripts, and the raw results behind every table and figure of the paper.

## Layout

| Path | Contents |
|---|---|
| `vista_siem/parties/` | The parties: Edge Encryptor `ee.py`, Key Authority `ka.py`, Token Directory `td.py`, Cloud SIEM `cloud.py`, Security Analyst `sa.py` |
| `vista_siem/crypto/` | Paillier (with offline randomizer precomputation), Merkle Mountain Range with multiproofs, sorted Merkle dictionary (membership and absence proofs), AES-GCM / HMAC-PRF / HKDF / Ed25519 wrappers, Count-Min sketch |
| `vista_siem/aqrs.py`, `laph.py`, `lineage.py` | Query hiding (AQRS), padding, and the authenticated computation lineage (ACL) commitments |
| `vista_siem/baselines/` | Re-implementations or cost models of the compared schemes (EVSEB, MK-Tree, PriSIEM, and others) |
| `vista_siem/data/` | Synthetic workload generator and the AIT-LDSv2 loader |
| `experiments/` | One script per experiment, plus `run_journal_v3.sh` (the full AWS run) |
| `tests/` | 96 tests, including tamper-detection tests for every verification path |
| `tools/` | AIT-LDSv2 fetcher, Wazuh replay setup, TFHE and pairing micro-benchmarks (Rust), `paper_ci.py` (confidence intervals) |
| `results/` | Raw CSVs and summaries of the runs reported in the paper (see below) |

## Setup

Python 3.11 or later, with GMP for `gmpy2`.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,experiments]"          # add ",baselines" for TenSEAL / PyTorch / LightGBM baselines
pytest -q                                     # about 30 s
```

## Names in the paper vs. the code

The code keeps the configuration names used during development. `experiments/common.py` defines them; `VISTA` is an alias of `J2R`.

| Paper | Code (`config(variant)`) |
|---|---|
| VISTA (complete system) | `J2R` (alias `VISTA`) |
| VISTA$_{k=3}$ | `J2R3` |
| VISTA-RawGraph | `J2` |
| VISTA-LAPH | `LAPH-E` |
| VISTA-NoPad | VISTA without padding (`S-NoPad` rows of the result files) |
| A2 (no history) | `A2` / `NoHist` |
| Fixed-Decay, Fixed-Window, No-Graph | `FixedDecay`, `FixedWindow`, `NoGraph` |
| PT-VISTA, ML-IF, ML-GB, Wazuh-T/D | `PT-S`, `ML-IF`, `ML-GB`, `B1-tuned` / `B1-default` in `ait_eval.py` |

Result files written before the rename label the complete system `S` (and `S-NoPad`, `S, k=5`, ...). In the paper, these are VISTA, VISTA-NoPad, and so on.

The revision's design switches are on by default:
- `aqrs_verify="all"`: every cohort member is verified alike, and the whole cohort is rejected on any failure;
- `inv_cohort=True`: investigations query the whole group;
- the encrypted group partition is bound in each checkpoint.

`aqrs_verify="real"` and `inv_cohort=False` reproduce the earlier behaviour.

## Reproducing the paper

The timings in the paper come from one AWS EC2 `m7i.2xlarge` (8 vCPU, 32 GB, Ubuntu 24.04); `docs/aws.md` explains the setup. The Exp. 5/6 cost figures of the revision were measured on an Apple M4 laptop (`results/laptop-r1`).

```bash
bash experiments/run_journal_v3.sh            # full run, several hours; --quick for a dry run
```

| Paper item | Script | Results |
|---|---|---|
| Table 2: synthetic detection | `e1_accuracy.py`, `e3_d29_design.py` (part A) | `vm-m7i-2xlarge-final/e1_*`, `vm-m7i-2xlarge-journal-v2-design/e3_d29_design_A.csv` |
| Table 3, Fig. S2: AIT-LDSv2 detection | `ait_eval.py` (+ `tools/wazuh_*` for Wazuh) | `vm-m7i-2xlarge-journal-v2/ait_journal_v2_e1_*`, `vm-m7i-2xlarge-journal-v3/ait_journal_v3_e1_*`, `vm-m7i-2xlarge-final/wazuh_e1.*` |
| Fig. 2: latency vs. N, q/N, j_q | `e2_acl_scale.py` | `vm-m7i-2xlarge-journal-v3/e2_acl_scale.*` |
| Exp. 2 throughput and per-event cost, Table S2, Fig. S3 | `e8_throughput.py`, `e_recent_baselines.py`, `e_baselines.py` | `vm-m7i-2xlarge-journal-v3/e8_*`, `vm-m7i-2xlarge-recent-baselines/`, `vm-m7i-2xlarge-final/baselines_*` |
| Table 4, Table S14: query identification | `e3_aqrs.py`, `e3_d29_design.py` (part B) | `vm-m7i-2xlarge-journal-v2/e3_aqrs_*`, `vm-m7i-2xlarge-journal-v2-design/e3_d29_design_B.csv` |
| Exp. 3 decoy discounting and filtered hunts | `e3_aqrs.py` (journal v3 options) | `vm-m7i-2xlarge-journal-v3/e3_aqrs_*_v3.*` |
| Table S13: volume leakage | `e3_d29_padding.py`, `ait_eval.py --parts e3` | `vm-m7i-2xlarge-journal-v2/e3_d29_padding.*`, `.../ait_journal_v2_e3_leakage.csv` |
| Fig. 3a: low-and-slow attackers | `e4_temporal.py --rates 1,2,3 --spans 24,48` | `vm-m7i-2xlarge-journal-v3/e4_temporal_hist_*` |
| Fig. 3b: epoch length | `e9_epoch_sweep.py` | `vm-m7i-2xlarge-journal-v3/e9_epoch_sweep.*` |
| Table S9, Table S3: gaps, dormancy, profile change | `e4_v2.py` | `vm-m7i-2xlarge-journal-v2/e4_v2_*` |
| Table S7: injected deviations | `e5_acl.py` | `vm-m7i-2xlarge-journal-v2/e5_acl_*` |
| Fig. 3c, Fig. S4: spot-checking | `e2_acl_scale.py --parts e` | `vm-m7i-2xlarge-journal-v3/e2_acl_spot_*` |
| Table 6: EE vs. cloud resources | `e7_split.py` | `vm-m7i-2xlarge-journal-v3/e7_split.*` |
| Fig. 3d, Table S10: verifying records | `e6_verify_reps.py` | `vm-m7i-2xlarge-journal-v3/e6_verify_reps.*` |
| Table S5: investigations | `e6_v2.py` | `vm-m7i-2xlarge-journal-v3/e6_v2*` |
| Exp. 5/6: cost of cohort-wide verification and group investigation | `e10_r1_costs.py` | `laptop-r1/e10_r1_*` |
| Table S8: timing spread | (from the runs above) | `vm-m7i-2xlarge-journal-v3/*` |
| Table S11: 95% intervals | `tools/paper_ci.py` | `vm-m7i-2xlarge-journal-v3/ci_summary.md` |

Every script accepts `--quick` for a small run. Output goes to `results/`, or to `$VISTA_RESULTS` if set.

## Data

- **Synthetic** (`vista_siem/data/synth.py`): benign multi-source background with injected brute-force, low-and-slow, exfiltration, and coordinated multi-source attacks, with exact ground truth. It is generated on the fly.
- **AIT Log Data Set V2.0** (Landauer *et al.*, [Zenodo 5789064](https://zenodo.org/records/5789064), CC BY-NC-SA 4.0). It is not redistributed here.
  - `python tools/ait_fetch.py` downloads only the text logs and labels, about 1 GB, into `~/data/ait-ldsv2/`, using HTTP range requests.
  - `vista_siem/data/ait.py` normalizes them into events and four incident classes.

## License

MIT (see `LICENSE`). The AIT-LDSv2 dataset keeps its own license.

## Citation

If you use this code, please cite the paper (citation to be added on publication).
