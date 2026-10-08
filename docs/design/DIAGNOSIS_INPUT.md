# Offline diagnosis input schema v1

v0.1 P1 reads saved RefScope run bundles. It does not rank candidates.

A bundle keeps the v0.0.2 files (meta.json, events.jsonl, stacks.json,
summary.json) and adds meta.diagnosis with schema version 1, stable content
run_id, manual label (good, bad, or unlabeled), original input hashes,
and explicit capture-quality fields. A labeled comparison requires at least one
good and one bad bundle. The command refscope timeline --bundle DIR --label good|bad
packages an already saved capture; live record orchestration is deferred.

Each lifetime contains address, generation, origin, object class, suspicion flags,
and ordered semantic tokens. Lifecycle boundaries alone do not establish exact
per-reference identity; exact_identity_proven remains false unless all events
carry the same explicit reference_id. A token contains operation type, normalized function,
normalized stack fingerprint (or null), reason state/value, return class,
source function and available source locations, generation, and object class.
CALL_RETURN records do not alter observed GET/PUT balance. Unknown event types
are retained as op_type=UNKNOWN with their original type. A missing reason is
state=absent; an unresolvable raw reason is state=unknown; a named reason is
state=known. No token represents absence: absence is established only by
comparing run sequences.

Capture quality distinguishes incomplete capture, known/unknown loss accounting,
attempted/captured/dropped counts, stack errors, ambiguous generations, and null
stack fingerprints. Loss or incomplete capture remains visible to later diagnosis.
A run with ambiguous generation or incomplete capture must not support an EXACT
identity claim. This schema does not assign diagnosis confidence or rank candidates.

Offline replay requires the complete bundle and validates schema versions,
required metadata, summary, stack records, event hash, label, run ID, generation,
and input hashes. Repeated loading is deterministic.
