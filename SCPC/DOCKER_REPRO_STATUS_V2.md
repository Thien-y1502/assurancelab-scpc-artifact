# SCPC v2 Docker reproduction

- Image: `assurance-lab-scpc:v2-release`
- Image digest: `sha256:1d84116a431a18e1343c80717a05417efcefedee0d7e7e285d0e890ce9de9cdd`
- Command: `docker run --rm --network none ... assurance-lab-scpc:v2-release`
- Exit code: `0`
- Result: `DOCKER_PASS_BOUNDED_SIMULATION`

The v2 container replay used the independent-oracle runner from this packet.
This confirms reproducibility of the simulation harness only; enterprise
deployment remains out of scope.
