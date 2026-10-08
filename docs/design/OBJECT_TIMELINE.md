# Object Timeline Engine (v0.0.2 P1)

The offline engine in `src/timeline/engine.py` consumes saved RefScope
`record=event` JSONL records. It does not change capture, BPF programs, or
the v0.0.1 CLI.

## Identity and state

An instance is keyed by `(object address, generation)`. Each address keeps
an ordered generation list. A `CREATE` starts an explicit generation; a first
observed GET/PUT/FREE starts a `partial` generation because its origin was not
captured. Generations move `UNKNOWN -> LIVE -> DEAD`.

After FREE, a later non-CREATE event is never appended to the dead generation.
The engine starts a new partial generation and marks it
`ADDRESS_REUSE_AMBIGUOUS`. A later CREATE after DEAD starts a new explicit
generation. This is conservative: it prevents silent merging but does not
claim reuse when the stream cannot prove it.

GET and PUT are counted independently. `observed_balance` is exactly
`observed_gets - observed_puts`; a PUT with no compatible prior observed GET
sets `PUT_WITHOUT_PRIOR_GET`, and a nonzero final balance sets
`UNBALANCED_OBSERVED_OPS`. The engine does not pair individual operations.

Actual kernel refcount is a separate field. It remains unavailable unless an
input event explicitly contains `actual_refcount` or `kernel_refcount`.
The operation balance is never used to populate that field.

## Offline input/output

`Timeline.process` accepts decoded event dictionaries; `read_jsonl` reads
the existing JSONL event stream and ignores stack/summary records. The output
contains generation state, origin, event list, operation counts, suspicion flags,
and both refcount concepts. It can be serialized with `write_json`.

The offline timeline CLI is implemented in `src/timeline/cli.py` and dispatched by
`src/cli/main.c`. This milestone intentionally does not add pairing, root-cause
diagnosis, statistical comparison, or source/control-flow inference.

## P2 generation metadata

Each generation now persists active_reasons, tasks, CPUs, target identities, stack_fingerprints, and all event records in addition to lifecycle and balance fields. A non-CREATE event after DEAD starts a new partial generation and sets EVENT_AFTER_FREE plus ADDRESS_REUSE_AMBIGUOUS; an explicit CREATE starts a new explicit generation.

REFCOUNT_NONZERO_AT_END is emitted only when an explicit actual_refcount or kernel_refcount was captured and is nonzero at the final event. Operation balance remains observed_gets - observed_puts and is never used as actual refcount.

## P3 CLI renderer

The binary dispatcher preserves trace and doctor and delegates the timeline command to the offline Python engine located beside the build tree. The command accepts --input, --format text|json, --object and --generation. Both renderers consume the same filtered document, so lifecycle, balance, actual-refcount and suspicion semantics cannot diverge.

Malformed JSONL, unknown event types, missing object fields, invalid pointers and nonpositive generations return exit code 2 with a specific refscope/timeline diagnostic. No kernel attach occurs.

## P4 run bundle and stack fingerprints

The offline bundle writer writes meta.json, events.jsonl, stacks.json and summary.json. events.jsonl contains normalized event records with stack_fingerprint references; stack records remain separate in stacks.json. summary.json contains the reconstructed timeline and the original capture summary when present.

Stack fingerprints hash canonical symbol plus relative offset and, when available, source file:line. Raw instruction addresses are not part of the fingerprint. Lookup failure is persisted as lookup_failed=true and fingerprint=null. meta.json records kernel/architecture, optional Build IDs and vmlinux path, target hash, command line, capabilities, timestamp and input hashes.
