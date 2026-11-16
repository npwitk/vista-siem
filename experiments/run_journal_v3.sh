#!/usr/bin/env bash
# Journal v3 experiments (TCC major revision 1): spot-check ACL, EE/cloud split, throughput, long
# low-and-slow history regime, filtered hunts and decoy discounting, epoch-length sweep, AIT baselines
# PT-S / ML-IF / ML-GB. J2R = ACL + D29 + D30 (experiments/common.py).
#   VISTA_RESULTS=results/vm-m7i-2xlarge-journal-v3 bash experiments/run_journal_v3.sh     full run
#   bash experiments/run_journal_v3.sh --quick         dry run (default output results/laptop-journal-v3)
#   SKIP_AIT=1 ...                                     synthetic experiments only (no AIT steps)
#   SKIP_SCALE=1 ...                                   skip the 10^7 Exp 2 point (needs ~16 GB)
#   SKIP_DT_AIT=1 ...                                  Delta_e sweep on synthetic data only (the AIT part
#                                                      runs E1 three times, 300-s epochs being the slowest)
#   WORKERS=8 HEAVY_WORKERS=2 ...                      process pools (AIT full-scenario jobs: HEAVY_WORKERS)
# Every step logs to $OUT/logs/<step>.log; a failed step is reported and the run continues.
set -uo pipefail
cd "$(dirname "$0")/.."
Q="${1:-}"
W="${WORKERS:-8}"
HW="${HEAVY_WORKERS:-2}"
if [ -n "$Q" ]; then DEFAULT_OUT=results/laptop-journal-v3; else DEFAULT_OUT=results/vm-m7i-2xlarge-journal-v3; fi
OUT="${VISTA_RESULTS:-$DEFAULT_OUT}"
export VISTA_RESULTS="$OUT"
mkdir -p "$OUT/logs"
python -c "import platform,sys,os; print(platform.platform(), sys.version, os.cpu_count(), 'cpus')" > "$OUT/env_python_journal_v3.txt"
git rev-parse HEAD > "$OUT/env_commit_journal_v3.txt" 2>/dev/null || true
pip freeze > "$OUT/env_pip_journal_v3.txt" 2>/dev/null || true
FAILED=()
step() {  # step <name> <command...>
  local name="$1"; shift
  echo "== $name: $* ($(date '+%F %T'))"
  local t0=$SECONDS
  if "$@" > "$OUT/logs/$name.log" 2>&1; then
    echo "   ok in $((SECONDS - t0)) s"
  else
    echo "   FAILED after $((SECONDS - t0)) s (see $OUT/logs/$name.log)"; FAILED+=("$name")
  fi
}
QF=$( [ -n "$Q" ] && echo --quick )

step tests python -m pytest -q tests
NS="10000,100000,1000000,10000000"
[ -n "${SKIP_SCALE:-}" ] && NS="10000,100000,1000000"
# Exp 2/5: q/N, N to 10^7, j_q, S-FullHE, and (e) spot-check ACL cost and tamper detection vs f
step e2_scale python experiments/e2_acl_scale.py --ns "$NS" --parts abcde --reps 10 --workers "$W" $QF
# Exp 6: dual authentication and investigation latency (10 tamper trials, 10 latency repetitions)
step e5_integrity python experiments/e5_integrity.py --variant J2R --workers "$W" --bits 2048 --trials 10 \
  --latency-reps 10 $QF
step e6_v2 python experiments/e6_v2.py --variant J2R --workers 4 --bits 2048 --seeds 10 $QF
step e7_split python experiments/e7_split.py --bits 2048 --seeds 3 --workers 3 $QF          # EE vs cloud
step e8_throughput python experiments/e8_throughput.py --bits 2048 --workers 1,2,4,8 $QF    # events/s, 50.7 ms
# Exp 4: long low-and-slow regime (r in {1,2,3} per epoch, spans 24 and 48 epochs, 56-epoch streams)
step e4_hist python experiments/e4_temporal.py --workers "$W" --rates 1,2,3 --spans 24,48 --epochs 56 \
  --parts A --tag hist $QF
# Exp 3: filtered hunts (category and time filters), per-(entity, category) padding, decoy discounting
E3SYS=Direct,Fixed-5-G,J2R,Fixed-5-G+CP,Fixed-5-G+CPec,D29-G3
step e3_aqrs_v3 python experiments/e3_aqrs.py --workers "$W" --bits 512 --systems "$E3SYS" --time-frac 0.3 \
  --decoy-discount 0.5,0.7,0.9 --tag v3 $QF
# Delta_e sweep (synthetic always; AIT E1 per Delta_e unless SKIP_AIT or SKIP_DT_AIT; 2 injection seeds)
if [ -z "${SKIP_AIT:-}" ] && [ -z "${SKIP_DT_AIT:-}" ]; then
  step dt_sweep python experiments/e9_epoch_sweep.py --workers "$W" --systems J2R,S --epochs 300,900,3600 --ait \
    --ait-args "--workers $W --heavy-workers $HW --inject-seeds 2" $QF
else
  step dt_sweep python experiments/e9_epoch_sweep.py --workers "$W" --systems J2R,S --epochs 300,900,3600 $QF
fi
if [ -z "${SKIP_AIT:-}" ]; then                                                 # AIT-LDSv2 baselines
  step ait python experiments/ait_eval.py --parts e1 --tag journal_v3 --workers "$W" --heavy-workers "$HW" \
    --systems J2R,A2,PT-S,ML-IF,ML-GB --rules B1-default,B1-tuned $QF
fi
if [ ${#FAILED[@]} -gt 0 ]; then echo "failed steps: ${FAILED[*]}"; exit 1; fi
echo "done: $OUT/*.md"
