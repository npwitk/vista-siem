# Journal Experiment 4: multi-epoch correlation (synthetic data)

Seeds [1, 2, 3, 4, 5]; Part A streams of 56 epochs.


## Part A: low-and-slow, recall@FP2


Span 24 epochs

| System | r=1 | r=2 | r=3 |
|---|---|---|---|
| S | 0.00 | 0.07 | 0.80 |
| NoHist | 0.00 | 0.07 | 0.40 |
| FixedDecay | 0.00 | 0.07 | 0.73 |
| B1-default | 0.00 | 0.00 | 0.07 |

Span 48 epochs

| System | r=1 | r=2 | r=3 |
|---|---|---|---|
| S | 0.00 | 0.13 | 0.80 |
| NoHist | 0.00 | 0.07 | 0.47 |
| FixedDecay | 0.00 | 0.13 | 0.80 |
| B1-default | 0.00 | 0.00 | 0.20 |

## Part A: low-and-slow, ROC AUC


Span 24 epochs

| System | r=1 | r=2 | r=3 |
|---|---|---|---|
| S | 0.07 | 0.83 | 0.90 |
| NoHist | 0.37 | 0.81 | 0.91 |
| FixedDecay | 0.06 | 0.83 | 0.90 |
| B1-default | 0.48 | 0.51 | 0.57 |

Span 48 epochs

| System | r=1 | r=2 | r=3 |
|---|---|---|---|
| S | 0.05 | 0.82 | 0.91 |
| NoHist | 0.37 | 0.80 | 0.91 |
| FixedDecay | 0.05 | 0.81 | 0.91 |
| B1-default | 0.47 | 0.50 | 0.57 |

## Part A: low-and-slow, recall at the calibrated threshold


Span 24 epochs

| System | r=1 | r=2 | r=3 |
|---|---|---|---|
| S | 0.00 | 0.00 | 0.07 |
| NoHist | 0.00 | 0.00 | 0.33 |
| FixedDecay | 0.00 | 0.00 | 0.00 |
| B1-default | 0.00 | 0.00 | 0.00 |

Span 48 epochs

| System | r=1 | r=2 | r=3 |
|---|---|---|---|
| S | 0.00 | 0.00 | 0.00 |
| NoHist | 0.00 | 0.00 | 0.53 |
| FixedDecay | 0.00 | 0.00 | 0.00 |
| B1-default | 0.00 | 0.00 | 0.00 |

## Part A: low-and-slow, falsely alerted benign entities


Span 24 epochs

| System | r=1 | r=2 | r=3 |
|---|---|---|---|
| S | 1.60 | 1.40 | 1.40 |
| NoHist | 2.80 | 2.80 | 2.80 |
| FixedDecay | 1.40 | 1.40 | 1.40 |
| B1-default | 0.00 | 0.00 | 0.00 |

Span 48 epochs

| System | r=1 | r=2 | r=3 |
|---|---|---|---|
| S | 1.40 | 1.40 | 1.40 |
| NoHist | 2.80 | 2.80 | 2.80 |
| FixedDecay | 1.40 | 1.40 | 1.40 |
| B1-default | 0.00 | 0.00 | 0.00 |

Total time 508s
