# OCIL selection recovery

The source-backed Q3 2026 inventory contains **1,653 OCIL-only Rules** and
**7,239 Rules with OVAL and OCIL**. OCIL-only Rules now project to manual
Assessments. Where OVAL exists, OVAL remains the default automated choice and
OCIL is retained as a non-default manual alternative; both choices are not
made mandatory.

The projection retains source check identities, catalog references, component
IDs, and the original Rule hash. It does not execute OCIL or claim questionnaire
answer equivalence. Compound OCIL workflows remain a manual procedure rather
than an invented automated predicate.
