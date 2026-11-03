# SCPC bounded local results

Run: five seeds × 1,000 generated cases = 5,000 cases; finite audit schema has
256 exhaustive rows. The generator and labels are synthetic and were frozen in
`EXPERIMENT_CONTRACT.json`.

| Method | Accuracy | False-equivalence rate | Coverage | Witness completeness | Scope negative-control rate |
|---|---:|---:|---:|---:|---:|
| SCPC | 1.0000 | 0.0000 | 0.7324 | 1.0000 | 1.0000 |
| Strict exact | 0.5038 | 0.0000 | 0.2362 | 0.0000 | 1.0000 |
| Ontology rule | 0.7116 | 0.2884 | 0.8900 | 0.0000 | 0.0000 |
| Keyword match | 0.4770 | 0.3528 | 0.8900 | 0.0000 | 0.0000 |
| Untyped crosswalk | 0.3462 | 0.6538 | 0.8900 | 0.0000 | 0.0000 |

The local success rule is satisfied. The result supports only the bounded
synthetic semantic classification claim. It does not establish official
standard equivalence, enterprise conformity, or a general theorem.

## Negative evidence retained

The labels are generated from the same finite relation grammar used by the
runner. This creates a construct-validity risk: an external adjudicated
crosswalk set could be harder or disagree with the generator. A human-labelled
and independently adjudicated benchmark is required before a paper-level claim.
