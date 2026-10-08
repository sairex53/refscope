# Offline cohort alignment (v0.1 input stage)

The diagnose command loads saved, versioned bundles and compares every good run with every bad run. This stage reports alignment only; it does not generate candidate causes, rank hypotheses, or infer root cause.

A cohort ID is a SHA-256-derived identifier over canonical JSON fields: target/object type, initial acquisition stack, optional creation stack, semantic reason set, generation, origin, and a small acquisition-side context. Pointer address, timestamps, CPU, and task ID are not cohort keys. Repeated members with an identical cohort signature are marked ambiguous-cohort-membership; they are not paired arbitrarily.

Within a cohort, weighted LCS aligns tokens in order. Different operation types cannot pair. Pair weights are operation type 64, reason 16, normalized stack 8, source function 4, and return class 2; gaps cost 24. Timestamps are ignored. Stable tie-breaking makes identical inputs produce identical JSON.

The result includes matched, good-only, and bad-only tokens; earliest unmatched or semantically different token; a radius-three context (up to seven events per side); cohort ID; and both run IDs. CPU/task variation does not prevent alignment. Separate generations remain separate cohorts. A cohort with uncertain/partial identity is not upgraded to exact identity by this algorithm.

## Candidate rules and confidence (v0.1)

Candidate rules consume aligned tokens and remain heuristic evidence, never proof of root cause. The initial acquisition reason is the cohort reason anchor; reasons on later operations stay in the token sequence so missing transfer/release behavior remains comparable.

The explicit rules are unmatched acquisition, extra release, early final release, ownership-transfer divergence, and error-path divergence. Scores expose signed components in both output formats. Available components include unique operation mismatch (+3), good-pattern recurrence above 80% (+3), acquisition-stack stability (+2), adjacency to error return (+2), explicitly captured refcount corroboration (+2), matching semantic reason (+2), dropped/unknown-loss penalty (-2), uncertain generation penalty (-2), and equivalent-candidate penalty (-3). No observed balance is used as actual refcount.

Confidence describes evidence quality: EXACT requires a shared explicit identity key on both lifetimes and no warnings; STRONG requires at least two good runs, a good-pattern recurrence above 80%, sufficient score, and no warnings; all other cases are INFERRED. Capture-quality warnings are copied to each candidate and prevent promotion. Every candidate has root_cause_proven=false.
