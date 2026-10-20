# Lab Evidence

This directory holds artefacts captured during live lab validation runs.

| File pattern | Contents |
|---|---|
| `lab_run_YYYYMMDD_HHMMSS.log` | Full pytest output from `make lab-test` |
| `hunt_report_*.json` | HuntReport JSON from each S4/S11 run |
| `actions_*.json` | brain_actions snapshot after containment tests |
| `kill_switch_*.json` | Kill-switch engage/disengage API responses |

Files in this directory are excluded from `.gitignore` by default.
Do not commit sensitive customer data here.
