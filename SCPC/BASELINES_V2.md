# SCPC v2 baseline fairness

Every method receives exactly the same 30,000 cases, source/target attribute
sets, scope flag, conflict flag and seed partition. No method receives extra
features, tuning data or a different stopping rule. Paired differences are
reported across the same five seed blocks.

- `strict_exact` is the conservative zero-false-equivalence comparator.
- `ontology_rule` is a stronger high-coverage but untyped comparator.
- `keyword_match` and `untyped_crosswalk` expose lexical/untyped failure modes.

These are source-faithful algorithmic baselines for the declared relation
calculus. They are not a substitute for an external human-adjudicated
standards crosswalk, which remains outside this simulation-only contract.
