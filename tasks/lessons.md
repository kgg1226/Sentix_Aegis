# Lessons learned

## 2026-03-25 — Project bootstrap
- Fitness function v1 had 12 critical defects (AEGIS-F001 through F012). All magic numbers need empirical calibration, not hand-tuning.
- Naive gyroscope (balance restoration) is harmful during intentional asymmetry (wartime). Adaptive homeostasis with moving target is the correct approach.
- Detection confidence → action mapping is a POLICY problem, not an algorithm problem. Never auto-block below 0.90 confidence.
