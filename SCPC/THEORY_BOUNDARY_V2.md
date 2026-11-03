# SCPC v2 theory boundary

The runner checks implementation agreement with an independent oracle on 4,096
finite schema rows and 30,000 density-shifted random cases. It also checks that
scope and conflict ablations create the predicted safety failures.

This is stronger than reusing the production label function, but it is still
not a general proof. The remaining proof gate is a structural-induction proof
for the typed relation algebra over composed graphs, with explicit admissible
model assumptions and countermodels.
