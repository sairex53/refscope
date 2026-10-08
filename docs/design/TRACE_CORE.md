# Trace core development contract

Implementation: C/libbpf skeleton, CO-RE register reads, one configured BPF object
per target, with shared ring buffer, per-CPU counters, and stack map. No object
memory is dereferenced. Target definitions are internal data, not target-specific
BPF logic. YAML import remains experimental; return probes are optional for this
version and tracepoint adapters are deferred.

## Schema 1

`include/refscope/event.h` defines the binary event record. JSONL record kinds:

- event: schema_version, monotonic ts_ns, per-CPU sequence, cpu, pid (TGID), tid,
  comm, object (hex), ip (hex), target_id, type, function, reason, stack_id,
  stack_lookup_failed;
- stack: schema_version, stack_id, frames (ip, nearest kernel symbol, offset);
- summary: schema_version, captured, loss_counters_known, attempted, dropped,
  drop_rate, ring_dropped, nested_dropped, stack_errors,
  userspace_stack_lookup_errors, kprobe_misses, kernel_miss_snapshot,
  transport_complete, incomplete.

Valid UTF-8 in JSON strings is preserved. Control characters, quotes and
backslashes are escaped. Invalid non-UTF-8 bytes are represented with `\u00xx`
escapes so that emitted JSON remains valid.

Identity is `(capture session, cpu, sequence)`, not timestamp alone.

`attempted` counts post-filter BPF invocations. Accepted non-nested invocations
receive a per-CPU sequence before ring reservation. A ring reservation failure
therefore leaves a sequence gap. A same-CPU nested invocation rejected by the
reentrancy guard increments `nested_dropped` and does not receive a sequence.

`dropped` is the sum of `ring_dropped` and `nested_dropped`.

Reason is raw unsigned argument bits or null; it is not interpreted as a
refcount value.

Negative stack_id is a BPF stack-capture error, or -1 when stacks are disabled.
Kernel stack-capture errors are counted in `stack_errors`. A userspace stack-map
lookup failure does not discard the already delivered event: the event has
`stack_lookup_failed=true`, and the failure is counted separately in
`userspace_stack_lookup_errors`.

Stacks are never overwritten or reused on collision by the application.

IP is the target symbol address for fentry and saved instruction pointer for
kprobe. Symbol resolution requires visible kallsyms addresses. Optional libdw
source file:line resolution checks the ELF build ID against the kernel notes and
falls back to symbol+offset. Fixture cases and a real matching running-kernel
capture pass on the current AArch64 guest.

With `--backend auto`, a target whose fentry load or attach fails may fall back to
kprobe unless that kprobe is blacklisted. Fallback reuses the already prepared
events/stats/stacks maps; forced fentry does not fall back. A failed replacement
causes all previously attached links and prepared skeletons to be cleaned up.

## Loss and completeness semantics

When the per-CPU stats map is readable:

- `loss_counters_known=true`;
- attempted/drop/stack counters are numeric;
- counter aggregation is checked for unsigned overflow.

If stats cannot be read or aggregation overflows:

- `loss_counters_known=false`;
- attempted, dropped, drop_rate, ring_dropped, nested_dropped and stack_errors
  are JSON null;
- `transport_complete=false`;
- `incomplete=true`;
- capture returns nonzero.

`transport_complete` describes RefScope's own event transport accounting. It is
true only when the counters are known, no prior capture/output error occurred,
and:

`captured == attempted - dropped`

It does NOT mean:

- zero instrumentation loss;
- complete object lifetime observation;
- complete kernel instrumentation;
- zero kernel-side kprobe/fentry misses.

A capture with known drops can therefore have `transport_complete=true` while
`incomplete=true`.

`incomplete=true` when any known RefScope drop occurred, stack collection or
userspace stack lookup was incomplete, transport accounting failed, or loss
counters are unavailable.

The summary reports `kprobe_misses` when the link info API exposes it and sets it
to `null` when unavailable. `kernel_miss_snapshot=true` marks the supported
detach-time snapshot limitation; a zero value is not proof that lifetime kernel
misses were zero. This counter is therefore observability, not a completeness
claim.

## Ordering and reentrancy

No global timestamp sort or total-order claim is made.

Stats and sequence state are per CPU. A nonblocking per-CPU atomic reentrancy
guard serializes sequence issuance through ring publication for accepted
same-CPU executions. If a probe executes again on that CPU while the guard is
held, the nested invocation is counted in `nested_dropped` and returns without
spinning.

The generated ARM64 BPF bytecode was inspected and contains the expected
`cmpxchg_64` guard operations and atomic counter updates. Normal kprobe and
fentry execution with the guard has passed verifier/JIT load and runtime capture
tests.

A test-only x86_64 module now forces a same-CPU hard-IRQ self-IPI while rs_ipi_target is active. Across 20 kprobe runs, the first entry, IPI handler, and recursive target entry all ran on CPU 0 while the worker ran on CPU 1; 40 events had sequence 1..40 and no ring or ordering errors. Evidence: local validation evidence (not included in this repository) The probe guard was not held across the interrupt in this setup, so nested_dropped=0 is expected and does not claim a guard-drop or NMI result. True NMI reentrancy remains unverified.

Across CPUs, ring-buffer reservation order determines userspace delivery order;
RefScope makes no global sequence ordering claim.

There is a startup interval between attaching individual target functions.
Workloads intended for complete capture must begin only after stderr `ready`.

Detachment also happens one link at a time. The implementation destroys all
links before the final ring-buffer consume, preventing new target events while
the final committed records are drained.

## Failure-path behavior

The current ARM64 correctness review has exercised these paths:

- normal duration timeout;
- SIGINT;
- SIGTERM;
- closed/broken stdout;
- first target attached followed by second-target attach failure;
- BPF skeleton open failure;
- shared-map reuse_fd failure;
- second-target BPF load failure;
- ring_buffer__new failure;
- stack-map lookup failure;
- ring_buffer__poll returning -EINTR;
- ring_buffer__poll returning a hard error;
- ring_buffer__consume returning a hard error;
- final loss-counter lookup failure.

Observed RefScope-owned BPF programs, maps and links were checked after these
tests and did not remain after process exit.

The failure injection used external LD_PRELOAD test shims. Production RefScope
contains no hidden fault-injection switch.

## Validation limits

BTF validation checks that the selected object argument is a pointer and that
the optional reason argument is an integer/enum no wider than 64 bits.

Without a matching BTF prototype, RefScope reports ABI-only validation. Symbol
presence does not prove traceability: permissions, kernel configuration,
blacklists and trampoline/kprobe restrictions can still make attachment fail.

Current BPF register support is explicitly limited at build time to:

- aarch64 / ARM64;
- x86_64 / x86 libbpf register macros.

ARM64 has been executed and tested. x86_64 execution is not yet validated.

Build currently requires `/sys/kernel/btf/vmlinux` in order to generate
`build/vmlinux.h`.

Not yet implemented or not yet fully validated:

- same-CPU hard-IRQ self-IPI reentry is validated; true NMI remains an additional
  post-v0.0.1 check because the available UTM VM has no hardware PMU;
- real runtime kernel probe-miss rates when the kernel does not expose a
  lifetime counter (the summary intentionally reports `null` in that case);
- comprehensive real-attach capability checks across kernels and policies;
- x86_64 runtime execution testing;
- fexit/kretprobe return events;
- tracepoint adapters;
- YAML target loading.

The items above are explicit v0.0.1 runtime-scope limits; the v0.0.2 offline timeline contract is documented below and does not claim those checks as timeline evidence.

## Final validation record — 2026-10-06

The current AArch64 binary and synthetic `refscope_test` module passed the
ordinary suite, 100/100 deterministic runs for fentry and kprobe, four-CPU
concurrent runs, 1,500,000-event stress runs, measured-drop overload runs,
filters, excluded workload, no-stacks, lifecycle/fault and cleanup checks.
The complete index, parameters, summaries, logs and hashes are outside the
repository at:

local validation evidence (not included in this repository)

The overload runs used a 4096-byte ring and measured nonzero drops; they are
not presented as complete capture. The stress runs used a 268435456-byte ring
and captured all 1,500,000 fixture events. These results are synthetic and
were executed on AArch64 only.

The final release decision is **v0.0.1 ГОТОВА по исходным обязательным критериям**.
The same-CPU hard-IRQ self-IPI test passed; true NMI is an additional post-release check. Matching source
lookup against build ID `9065d022a845f496d5c53dc7f90b6710fcc0a0ca` passed on
the current AArch64 guest. Ordinary concurrency is not substituted for the
NMI test. x86 runtime, fexit/kretprobe return events, tracepoint adapters and
YAML loading remain outside this v0.0.1 gate.

References used for transport/attachment semantics:

- https://docs.kernel.org/bpf/ringbuf.html
- https://github.com/libbpf/libbpf/blob/master/src/libbpf.h

## Final audit — 2026-10-07

The p4 full matrix was reused only after exact binary, production-source, backend, maps, stacks, summary and test hashes matched. No second identical matrix was launched. The evidence remains synthetic and AArch64-only; matching-vmlinux source lookup passed in the real capture at local validation evidence (not included in this repository), while true NMI execution remains unverified; same-CPU hard-IRQ self-IPI reentry is evidenced at local validation evidence (not included in this repository)


## v0.0.2 offline timeline contract

The timeline engine consumes saved event JSONL and does not attach BPF probes. It keys
state by `(object address, generation)`, tracks `UNKNOWN → LIVE → DEAD`, and keeps
`observed_balance` separate from `actual_refcount`; the latter is `null` unless an
input record explicitly captures it. A complete CREATE/FREE stream can establish a
generation; first-observed lifetimes are `origin=partial`, and post-FREE reuse without
proof is `ADDRESS_REUSE_AMBIGUOUS`. These flags are observability signals, not root-cause
diagnoses, and the engine does not pair individual GETs with PUTs.

The bundle format persists normalized `events.jsonl`, separate `stacks.json`,
`summary.json`, and metadata in `meta.json`. Stack fingerprints use symbol name,
relative offset and source line, excluding raw ASLR addresses. Offline replay requires
saved event JSONL; full bundle replay additionally uses the saved stack, summary and
metadata files. Current v0.0.2 matrix evidence is recorded at
local validation evidence (not included in this repository).

## v0.1 offline differential validation — 2026-10-07

The offline diagnosis layer (`src/diagnosis/`) consumes saved versioned run bundles, constructs cohorts, aligns semantic tokens, and applies explicit candidate rules. Candidate output includes run/cohort IDs, divergence windows, source locations when present, score components, confidence, evidence, and capture-quality warnings. It reports candidates, not proven root causes; `EXACT` is reserved for explicit shared identity evidence. The human-readable top-candidate report is bounded to 30 lines by the CLI test.

The synthetic suite passed eight scenarios over ten repetitions each: top-3 100%, missing-PUT and double-PUT top-1 100%, false `EXACT` 0. Simulated drops/incomplete capture reduce confidence and are surfaced as warnings. This demonstrates offline model behavior only.

**Known-subsystem gate remains unverified.** RxRPC is available as a kernel module but no controlled good/bad repro, known divergent lifetime path, test workload, or saved captures are present on this host; its module debuginfo is also unavailable. The matching kernel `vmlinux` does not stand in for module DWARF. No RxRPC support claim is made. v0.1 remains **not ready** until a known real subsystem divergence can be reproduced and narrowed to a candidate. Evidence: local validation evidence (not included in this repository).

## v0.2 provenance and discovery — final matrix, 2026-10-08

The offline provenance model orders pairing evidence as direct tracker token,
unique semantic reason, unique stable stack/path signature, then sequence inference.
Only a unique direct `ref_tracker` token pair is `EXACT`. Reason-based pairing is
`STRONG`; path and sequence pairings are `INFERRED`. Equal-support candidates remain
unresolved with `ambiguous=true` and all hypotheses retained. Inferred edges do not
establish ownership.

Target-level `transfers` annotations model sending acquisition, transfer event,
receiving acquisition and receiving release. Missing receive-side acquisition is
reported as `MISSING_RECEIVE_SIDE_ACQUISITION`. CPU/task changes do not invalidate an
offline transfer, and serialized transfer evidence explicitly says
`ownership_proven=false`.

`inspect-target` and source/BTF discovery are offline. Generated YAML is editable and
requires manual review. Candidate lists are not auto-attached: only operations
explicitly present in the selected target specification translate to existing
`--get`, `--put`, `--create`, and `--free` capture options. Discovery does not install
probes for every discovered function; the capture CLI rejects more than 32 selected
target functions. Missing source/BTF results in manual mode. On
the current host, tracefs access was denied, so native production tracepoint use was
not validated; adapter behavior and manual fallback passed synthetic tests.

Three synthetic target styles (explicit get/put with reviewed reason, kref, and
ref_tracker) yielded 3/3 acquire and 3/3 release precision/recall, with zero false
high-confidence candidates and zero false `EXACT`. This does not measure generalized
production discovery accuracy. Final v0.2 matrix and hashes:
local validation evidence (not included in this repository).

The RxRPC known-case limitation remains a separate v0.1 release-gate item: no real
known-good/known-bad RxRPC workload with matching module symbols is available.
Synthetic diagnosis results are not RxRPC validation.
