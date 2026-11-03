# SCPC baseline roles

- `untyped_crosswalk`: any shared attribute is treated as equivalent.
- `keyword_match`: Jaccard-style lexical overlap threshold.
- `ontology_rule`: subset is refinement, but overlap is collapsed into
  equivalent and scope is not enforced.
- `strict_exact`: exact attribute equality only; conservative but low coverage.

All methods see the same generated cases and no method receives additional
features. The proposed method is not compared against a weaker input budget.
