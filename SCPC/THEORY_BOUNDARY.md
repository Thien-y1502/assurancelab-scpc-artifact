# SCPC theory boundary

Executed: exhaustive finite soundness/witness checks over three attributes,
scope match, and conflict flag (256 rows). This is an implementation boundary
audit. It is not a proof of the intended general relation-calculus theorem.

Required next proof gates:

1. formalize the relation algebra and admissible model class;
2. prove relative soundness by structural induction over composed relations;
3. prove witness completeness for the declared finite schema;
4. test countermodels generated independently of the compiler;
5. mechanize or independently reimplement the proof checker.
