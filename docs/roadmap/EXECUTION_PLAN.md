# Execution plan — what to do each week

This file turns the version specifications into a practical work order.

## Week 1

### Day 1
- repository/build system;
- libbpf skeleton;
- capability detection;
- one fentry/kprobe target;
- ring buffer event output.

### Day 2
- get/put target specification;
- stack map;
- symbolization;
- JSONL;
- dry-run.

### Day 3
- synthetic kernel target;
- deterministic correctness tests;
- event-drop accounting.

### Days 4–5
- per-object timeline;
- generation model;
- saved run bundle;
- pointer-reuse tests.

### Days 6–7
- real subsystem validation;
- start RxRPC/native-trace comparison if useful.

**Goal:** v0.0.2.

## Week 2

- good/bad run labels;
- stack/event normalization;
- sequence alignment;
- first-divergence calculation;
- unmatched acquisition/release rules;
- confidence model;
- synthetic injected-bug corpus.

**Goal:** v0.1 prototype that explains deliberately injected bugs.

## Week 3

- improve cohorting;
- source file:line;
- ranking score;
- reduce report to top candidates;
- test noisy multithreaded cases;
- select first real syzbot lifetime/refcount bug.

## Week 4

- reproduce real bug reliably;
- build target config;
- capture failing executions;
- obtain good/comparison executions where possible;
- run diagnosis;
- verify manually.

**Decision point:** if the tool adds no value, stop adding features.

## Weeks 5–8

Only if first real case is promising:

- target inspector;
- explicit provenance model;
- ref_tracker/native tracepoint ingestion;
- second/third real bug;
- upstream patch(es);
- syzbot case directory/report automation.

**Goal:** v0.3 with a real upstream story.

## Months 3–4

Only if v0.3 proved value:

- kref + additional refcount model;
- async transfer modeling;
- target schema;
- x86_64 + arm64;
- 5 real cases;
- graph/JSON;
- benchmarks.

**Goal:** v0.5.

## Months 5–7

- external users;
- packaging;
- capability matrix;
- schema stabilization;
- regression CI;
- docs;
- performance hardening.

**Goal:** v0.8.

## Months 6–12+

Tag v1.0 only when evidence gates in `v1.0_STABLE.md` are actually met.

## Time-saving rules

1. Do not build a TUI before a real bug is solved.
2. Do not add AI before deterministic rules fail on measured cases.
3. Do not support a new refcount model without a real target case.
4. Do not reimplement QEMU/syzkaller/ktest functionality unless integration is impossible.
5. Do not implement generic tracing features already available in mature tools unless RefScope specifically needs them.
6. Every week must end with a runnable demonstration or a documented falsification result.

## Highest priority metric each week

Week 1: event correctness.  
Week 2: diagnosis correctness.  
Weeks 3–4: real-bug usefulness.  
Weeks 5–8: repeatability across bugs.  
Months 3–4: generalization.  
Months 5+: external usability.

This ordering is deliberately designed to prevent spending six months on infrastructure before learning whether the core idea is useful.
