# SCPC reproduction

From the repository root:

```powershell
python handoff\q1_execution_2026-11-03\SCPC\run_scpc.py
```

Outputs are `raw_cases.jsonl` and `results.json`. The runner imports the local
`src/assurance_lab` package and records the interpreter and Docker probe. Docker
was unavailable during this run, so the container gate is explicitly
`NOT_TESTED`.
