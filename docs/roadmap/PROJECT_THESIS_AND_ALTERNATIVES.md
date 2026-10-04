# Project thesis, existing work, reasons to continue, reasons to quit, and alternatives

## Executive conclusion

RefScope is **not guaranteed** to become widely used. No honest plan can guarantee that.

It is worth attempting because there is a real and current gap between:

- tools that detect a lifetime/refcount failure;
- tools that trace kernel execution;
- subsystem-specific reference trackers;
- static research systems that find reference-counting bugs;

and a practical runtime tool that takes an already reproducible failure and turns it into a **reference-provenance/root-cause explanation**.

However, the gap is narrower than "nobody has ever traced references". That claim would be false.

The project should therefore be built around one differentiator:

> **automatic object-centric correlation + good/bad differential analysis + ranked root-cause explanation**

—not raw tracing.

---

# 1. What already exists and why it matters

## Linux `ref_tracker`

Linux already has `ref_tracker_alloc()` / `ref_tracker_free()` infrastructure. It records acquisition and release stack traces for explicitly instrumented references and keeps active/dead tracker state.

Implication for RefScope:

- "record stacks for get/put" is not novel;
- exact per-reference provenance is possible when the subsystem explicitly carries tracker tokens;
- RefScope should be able to ingest/use this information when available instead of duplicating it.

## `debugobjects`

Linux has generic object-lifetime debugging infrastructure for detecting operations such as use of uninitialized/freed objects.

Implication:

- generic "object lifetime checker" is not a novel description;
- RefScope must explain *which ownership/reference path caused the bad lifetime*, not merely detect invalid lifetime state.

## KASAN/KFENCE/kmemleak

These are highly valuable detectors of memory corruption/leaks but do not generally answer which earlier reference transfer caused the lifetime error.

Implication:

- RefScope should consume their reports as trigger/context, not compete with them as a detector.

## `retsnoop`

`retsnoop` is a mature BPF-based non-invasive kernel function tracing tool that can trace many functions, arguments, returns, stacks and error paths.

Implication:

- writing a generic "trace arbitrary kernel functions with BPF" layer from scratch is wasted effort;
- RefScope capture should be deliberately narrower;
- architecture should allow consuming data from existing tracing backends, or at least copy the proven design principles instead of competing on tracing ergonomics.

## 2026 `refcount_final_put` patch series

A v5 Linux patch series posted in August 2026 proposed a tracepoint for the moment a `refcount_t`/`percpu_ref` reaches its final put. Its motivation explicitly says final-put knowledge significantly reduces UAF debugging effort and that alternative dynamic tracing is costly, especially for remote fuzzers.

Important: this plan does **not** assume that series is merged. It treats the discussion itself as evidence that better reference-lifetime observability remains an active problem.

## DrvHorn (2026)

DrvHorn is a static analysis/reasoning system for Linux driver reference-counting bugs. Its paper reports 545 true bugs, 424 previously unknown, and 45 merged fixes.

Implication:

- "automatically find refcount bugs" is not novel;
- RefScope should not position itself as a replacement for static verification;
- runtime diagnosis of a concrete reproducer is the defensible niche.

## syzkaller/syzbot

Syzbot already:
- fuzzes kernels continuously;
- attempts reproducer generation/minimization;
- performs cause/fix bisection where possible;
- publishes crash logs/configs/images/artifacts.

The missing human-heavy step is often understanding *why* the failing lifetime/control flow happened and writing a correct minimal fix.

That is the point RefScope should attack.

---

# 2. The precise niche

RefScope should answer:

```text
Given:
- a kernel build,
- a reproducer,
- an affected object/refcount model,
- and one or more successful/failing executions,

tell me:
1. which object instance is relevant;
2. where references were acquired/released;
3. how the failing lifetime differs from normal lifetimes;
4. which acquisition/release/ownership-transfer is unmatched or suspicious;
5. what source path is the best root-cause candidate;
6. how certain that conclusion is.
```

It is **not** required to prove a formal theorem.

It is required to produce a small, source-oriented hypothesis that saves human debugging time.

---

# 3. Fundamental technical limitation

A raw `refcount_t` contains a number, not ownership identities.

If the count is 4, it does not encode:

```text
ref #1 = workqueue
ref #2 = socket
ref #3 = timer
ref #4 = user
```

Therefore universal exact pairing of every GET with every PUT is impossible without extra semantics.

RefScope must explicitly model three confidence classes:

### EXACT
Evidence explicitly identifies the reference:
- `ref_tracker` token;
- subsystem reason enum that uniquely identifies ownership;
- explicit acquire/release API with unambiguous pointer flow.

### STRONG
No explicit token, but:
- call stack + reason + control-flow context make pairing effectively unique;
- repeated good executions agree;
- failing run has one clear unmatched operation.

### INFERRED
The diagnosis is based on differential patterns/statistics and may have alternatives.

Every report must state the confidence and alternative candidates.

If the project hides this limitation, it will lose credibility with kernel developers.

---

# 4. Why doing RefScope is not automatically "for nothing"

Even if it never becomes a standard Linux tool, reaching v0.3 gives concrete outputs:

- real libbpf/eBPF/BTF/kernel tracing experience;
- kernel object-lifetime/refcount understanding;
- repeatable syzbot reproduction infrastructure;
- potentially upstream Linux fixes;
- a case-study repository showing root cause → patch;
- a tool that can speed up your own future kernel bug work.

The strongest outcome is not "10k GitHub stars". It is:

```text
RefScope diagnosed bug A → upstream fix
RefScope diagnosed bug B → upstream fix
RefScope diagnosed bug C → upstream fix
```

That is visible evidence of usefulness.

---

# 5. Reasons RefScope may be a bad project

You should actively try to disprove the project.

## Risk 1 — tracing changes timing
Many lifetime bugs are races. Instrumentation may make the bug disappear.

Mitigation:
- filters;
- sampling;
- minimal capture;
- ability to use existing tracepoints;
- support offline crash metadata such as final-put information where available.

Kill signal:
- most target bugs stop reproducing under necessary instrumentation.

## Risk 2 — reference APIs are inlined
You often cannot attach to low-level `refcount_inc()` itself.

Mitigation:
- trace subsystem wrapper functions;
- consume explicit tracepoints;
- optional source/IR analysis;
- `refcount_final_put` if available.

Kill signal:
- useful targets generally have no observable wrapper/semantic boundary.

## Risk 3 — "good execution" may not exist
Some reproducers always fail.

Mitigation:
- compare earlier/later object instances;
- compare control-flow cohorts;
- compare patched vs unpatched kernel;
- compare same reproducer under conditions that suppress trigger.

Kill signal:
- differential analysis is unusable for a large fraction of selected bugs.

## Risk 4 — output is just another verbose trace
This is the biggest product risk.

Kill signal:
- after v0.1, a human still has to manually scan thousands of events and do the real reasoning.

## Risk 5 — existing tools are sufficient
`ref_tracker`, custom tracepoints, KASAN stacks, retsnoop, drgn and manual code reading may already solve a specific bug quickly.

Kill signal:
- RefScope does not reduce diagnosis time on at least one real case by v0.3.

---

# 6. Hard kill criteria

Stop or pivot if, after 6–10 serious weeks:

1. You attempted at least 5 appropriate real reproducible lifetime/refcount bugs.
2. RefScope produced no root-cause hypothesis that was materially better than KASAN + retsnoop/manual tracing.
3. It has not helped produce one credible patch.
4. Its useful mode requires extensive hand-written instrumentation for every new bug.
5. A newly found public project already implements essentially the same workflow better.

Do not keep working merely because sunk cost is high.

---

# 7. Alternatives: could something be more influential/visible in the same time?

Scores: 1 = low, 5 = high.

| Project | Impact ceiling | Chance of impressive result in 1–2 months | Novelty/defensibility | Adoption path | Difficulty |
|---|---:|---:|---:|---:|---:|
| **RefScope** | 4 | 4 | 4 | kernel/security/debugging | 4 |
| **scx-autopilot: closed-loop p99 scheduler tuner** | 5 | 4 | 3 | sched_ext/server performance | 4 |
| **TailPath: causal tail-latency root-cause profiler** | 5 | 3 | 4 | production observability | 5 |
| **SyzDiag: generic syzbot RCA/patch agent** | 4 | 4 | 2 | syzkaller workflow | 3 |
| **NetSched: NIC/RSS/IRQ + sched_ext co-optimizer** | 5 | 2 | 5 | high-performance servers | 5 |
| **Direct upstream sched_ext/scx contributions** | 4 | 5 | 2 | immediate existing community | 3 |
| **Production C/C++ memory-safety runtime** | 5 | 1 | 4 | compiler/runtime ecosystem | 5 |
| **New io_uring zero-copy RPC framework** | 4 | 2 | 2 | app/server ecosystem | 5 |

---

# 8. Alternative A — `scx-autopilot`

## Idea
Automatically classify latency-critical/background tasks and tune a `sched_ext` policy using measured p95/p99 latency and CPU/cache/queue pressure.

## Why it can be more influential than RefScope
`sched_ext` is upstream Linux. Meta publicly reported production benefits from a workload-specific sched_ext policy including a 28% reduction in one ads-serving p99 stage and fleet-level power savings.

A robust generic optimizer that gives even 5–15% tail-latency wins on common workloads could have direct infrastructure impact.

## Why it may be worse
- the `scx` ecosystem is already active and production-oriented;
- `scx_layered` is already highly configurable and production-capable;
- Oracle `bpftune` already establishes BPF-driven auto-tuning as a concept;
- performance gains are hardware/workload-specific;
- proving "generic" wins is much harder than producing a demo win;
- a scheduler that helps Redis may hurt PostgreSQL or mixed workloads.

## Verdict
**Higher ultimate infrastructure upside than RefScope, lower novelty, and higher risk of producing a benchmark trick rather than a generally useful project.**

Best if your primary goal is server performance rather than kernel debugging.

---

# 9. Alternative B — `TailPath`

## Idea
For one slow request, reconstruct where its wall time went:

```text
request
→ userspace CPU
→ runqueue delay
→ lock wait
→ block I/O
→ network wait
→ response
```

Then automatically rank the dominant kernel cause for p99 outliers.

## Upside
This is directly useful to production backend teams.

## Problem
End-to-end request identity across threads/async I/O is hard; existing eBPF/perf/observability tools already cover pieces of the problem. A genuinely causal version is a major project.

## Verdict
Potentially more commercially useful than RefScope, but likely **3–9+ months before a convincing generic result**.

---

# 10. Alternative C — generic syzbot RCA/patch agent

## Idea
Input a syzbot report; automatically reproduce, inspect source, trace, diagnose, propose and validate a patch.

## Problem
The space is getting crowded:
- AutoKFL research performs Linux kernel fault localization with dynamic reproduction;
- SyzScope analyzes security impact;
- new AI-driven kernel crash/patch projects already exist;
- syzkaller itself is experimenting with AI-assisted triage.

## Verdict
Easy to make a flashy demo, harder to create durable technical differentiation.

RefScope's narrower lifetime/provenance scope is more defensible.

---

# 11. Alternative D — `NetSched`

## Idea
Jointly optimize:
- NIC RX queues/RSS,
- IRQ affinity,
- RPS/XPS,
- CPU topology/NUMA,
- worker placement through sched_ext,

so a request remains cache/NUMA-local from packet ingress to application worker.

## Upside
If it works, this attacks a fundamental server fast path and can produce very real throughput/tail-latency wins.

## Downside
- NIC/hardware-specific behavior;
- difficult benchmarking;
- concurrency and topology complexity;
- hard to make portable;
- likely much longer than RefScope to stable.

## Verdict
**Probably the most ambitious/high-upside alternative**, but not the same-risk/time project.

---

# 12. Alternative E — direct `sched_ext/scx` upstream work

If the goal is simply "get noticed by strong Linux performance engineers as fast as possible", contributing directly to an active upstream ecosystem can beat launching a new project.

A good patch/feature/benchmark accepted by `scx` has immediate reviewers/users.

But it creates less "this is my tool" identity.

## Verdict
**Fastest path to relevant community contact; not necessarily the biggest standalone project.**

---

# 13. My recommendation

## If the goal is: "highest probability of a serious visible result in the next 1–3 months"

Continue **RefScope through v0.3**.

Why:
- it matches your current kernel/syzbot work;
- you already understand the bug class;
- real public bug reports are readily available;
- success can be demonstrated by an upstream fix, not synthetic benchmarks;
- the niche is narrower and more defensible than a generic AI RCA agent.

## If the goal is: "maximum possible direct impact on production servers over 6–12 months"

`scx-autopilot` or eventually `NetSched` has a higher ceiling.

But the risk-adjusted chance that a single developer gets a credible, broadly useful result quickly is lower.

## Best strategy

Do **not** commit mentally to a 12-month RefScope rewrite.

Commit to this experiment:

```text
4–8 weeks
↓
RefScope v0.1/v0.3
↓
attack several real bugs
↓
measure whether diagnosis became faster
```

If you get a real fix and positive maintainer feedback: continue.

If not: pivot to `sched_ext/scx` performance work with the tracing/BPF skills you just learned.

That makes the first 1–2 months useful even if RefScope itself is abandoned.

---

# 14. Research references used for this decision

- Linux object-lifetime debugging (`debugobjects`): kernel.org documentation.
- Linux `ref_tracker`: current kernel source (`lib/ref_tracker.c`, `include/linux/ref_tracker.h`, networking users).
- `retsnoop`: Andrii Nakryiko's BPF kernel tracing project.
- `refcount_final_put`: Linux kernel mailing-list v5 patch series, 2026-08-13.
- DrvHorn: "Automatic Detection of Reference Counting Bugs in Linux Kernel Drivers", 2026.
- syzkaller documentation: reproduction, syzbot, bisection and downloadable artifacts.
- AutoKFL: Linux kernel fault localization with dynamic crash reproduction, 2026.
- SyzScope: automatic analysis of security impact of syzbot bugs.
- sched_ext Linux documentation and `sched-ext/scx`.
- Meta Engineering, 2026-07-13: workload-specific sched_ext policy for ads serving.
- Oracle `bpftune`: BPF-driven Linux system auto-tuning.

The purpose of these references is not to claim nobody has private tooling. That cannot be proven. They establish that raw tracing/refcount detection already exist and that RefScope must win specifically on **diagnostic correlation and explanation**.
