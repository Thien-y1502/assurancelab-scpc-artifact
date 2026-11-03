# AssuranceLab SCPC v2 artifact

Reproducibility repository for the **Proof-Carrying Semantic Crosswalk
(SCPC)** independent-holdout simulation v2.

SCPC evaluates typed semantic relations between versioned control statements.
It returns a decision together with an explicit witness instead of treating
keyword overlap as equivalence.

## What is included

- `SCPC/EXPERIMENT_CONTRACT_V2.json` — frozen seeds, density regimes and metrics.
- `SCPC/run_scpc_v2.py` — deterministic local runner.
- `SCPC/results.json` — executed v2 result and claim boundary.
- `SCPC/raw_cases_v2.jsonl` — generated evidence rows.
- `SCPC/BASELINES.md`, `SCPC/THEORY_BOUNDARY.md`, `SCPC/REDTEAM.md` — baseline,
  proof and adversarial-review records.
- `src/assurance_lab/` — source snapshot used by the runner.
- `SCPC/Dockerfile` — network-disabled container replay.
- `MANIFEST.sha256` — file-integrity manifest.

## Reproduce locally

Python 3.12 is the reference runtime and the runner has no third-party
dependencies.

```bash
python SCPC/run_scpc_v2.py
python -c "import json; print(json.load(open('SCPC/results.json'))['status'])"
```

Expected status: `PASS` with claim state `BOUNDED_SIMULATION_PASS`.

## Reproduce in Docker

```bash
docker build --pull=false -f SCPC/Dockerfile -t assurancelab-scpc-artifact .
docker run --rm --network none assurancelab-scpc-artifact
```

The v2 container replay is an execution/reproducibility check. It is not an
enterprise conformity assessment or independent-host validation.

## Scientific boundary

The experiment uses five seeds and 5,000 generated cases plus a finite proof
audit. It supports only the bounded synthetic semantic-classification claim.
It does not establish official equivalence between standards, enterprise
conformity, or a general theorem. See `SCPC/CLAIMS.md` before citing results.

## License and citation

Code and artifact metadata are released under Apache-2.0. Cite the associated
paper only after the manuscript has been accepted; until then, use the commit
and the manifest hash for reproducibility.
