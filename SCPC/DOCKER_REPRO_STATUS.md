# SCPC Docker reproduction

- Image: `assurance-lab-scpc:20261103`
- Image digest: `sha256:d40354ad477ed287d6c448c905e824d983377d2951046819640568619392d845`
- Base image: `python:3.12-slim` (local cached digest)
- Command: `docker run --rm --network none ... assurance-lab-scpc:20261103`
- Exit code: `0`
- Network: disabled
- Result: `DOCKER_PASS_BOUNDED`

This confirms container replay of the local harness. It does not establish
enterprise deployment or independent-host replication.
