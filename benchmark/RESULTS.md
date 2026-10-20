# HydraX Benchmark Results

## Methodology

Precision (TP / (TP+FP)) is measured against labeled ground-truth targets.
Recall (TP / (TP+FN)) is tracked alongside precision so that FP reduction
cannot be gamed by suppressing all findings.

**Oracle requirement**: every `confirmed` finding must carry a `confirmation`
record with `reproduced: true` or a corroborating tool match.  Bare heuristics
are downgraded to `possible` and excluded from precision/recall counts.

## Targets

### test_target — http://localhost:9999
- TP=1  FP=0  FN=0  TN=0
- Precision: 100.00%
- Recall:    100.00%
- Confirmed findings: 1

## Combined Metrics

**Precision**: 100.00%  (gate: ≥ 95%)
**Recall**:    100.00%
**Gate**:      PASS ✓

## Static SPA Negative Set

Result: PASS ✓ (0 confirmed findings)

## How to run real targets

1. `docker run -d -p 3000:3000 bkimminich/juice-shop`
2. `docker run -d -p 4280:80 vulnerables/web-dvwa`
3. `python benchmark/runner.py`

Or via the Makefile: `make benchmark`
