# RefScope — roadmap to a stable, actually useful Linux kernel debugger

**Date of plan:** 2026-10-04

This directory is not a feature wishlist. It is a sequence of **go/no-go gates**.

The project should continue only while it proves that it saves real debugging time on real Linux kernel bugs.

## One-sentence thesis

RefScope should take a **reproducible Linux kernel lifetime/refcount bug**, reconstruct the lifetime of the affected object, compare good and failing executions, and report the most likely missing/extra reference operation or ownership divergence.

It must not be "another eBPF tracer".

## Files and reading order

1. `PROJECT_THESIS_AND_ALTERNATIVES.md` — why this project may be worth doing, why it may be a bad idea, existing competitors, kill criteria, and alternatives.
2. `v0.0.1_TRACE_CORE.md` — minimal non-invasive event capture.
3. `v0.0.2_OBJECT_TIMELINE.md` — object-centric lifetime reconstruction.
4. `v0.1_DIFFERENTIAL_DIAGNOSIS.md` — first version that can actually produce a root-cause hypothesis.
5. `v0.2_REFERENCE_PROVENANCE.md` — reference provenance, confidence levels, partial discovery of get/put semantics.
6. `v0.3_SYZBOT_WORKFLOW.md` — use on real syzbot bugs; first upstream proof.
7. `v0.5_GENERIC_ENGINE.md` — multiple refcount models/subsystems, async ownership transfers, reusable target descriptions.
8. `v0.8_ADOPTION_HARDENING.md` — portability, packaging, CI, reproducibility, benchmark suite, external users.
9. `v1.0_STABLE.md` — what "stable" must mean before you are allowed to call it 1.0.

## Version ladder

| Version | What it proves | Cumulative realistic time if working hard |
|---|---|---:|
| v0.0.1 | You can reliably capture manually-described reference events | 1–3 days |
| v0.0.2 | You can reconstruct one object's timeline correctly | 4–7 days |
| v0.1 | You can compare good/bad runs and rank a plausible divergence | 1–3 weeks |
| v0.2 | You can generalize provenance beyond one hand-written target | 3–6 weeks |
| v0.3 | RefScope helps diagnose real syzbot bugs and produces an upstream fix | 1–2.5 months |
| v0.5 | Works across several subsystems/refcount models | 2–4 months |
| v0.8 | Other people can install/use it without you | 4–7 months |
| v1.0 | Stable interfaces, evidence of repeatable value, real external adoption | 6–12+ months |

These estimates assume a strong coding agent and sustained work. They do **not** assume that every kernel bug reproduces reliably.

## The only metric that really matters

The project is successful when this loop works repeatedly:

```text
syzbot/reproducer
    ↓
RefScope
    ↓
specific root-cause hypothesis
    ↓
human verification
    ↓
minimal Linux fix
    ↓
upstream review/merge
```

GitHub stars, LOC, a TUI, a logo, or an "AI" label do not count as proof.

## Non-negotiable design rules

1. **Do not reimplement retsnoop.** Reuse existing kernel tracing primitives and keep the capture layer narrow.
2. **Never claim exact ownership when only inference exists.** Every diagnosis must carry a confidence class.
3. **Good/bad differential analysis is core functionality, not an optional feature.**
4. **The output must explain causality, not dump logs.**
5. **Real bugs are release gates.** Starting at v0.3, synthetic demos alone are insufficient.
6. **A feature that does not improve diagnosis time is not automatically valuable.**
7. **Kill or pivot if the tool cannot beat a competent human workflow after the v0.3 evaluation.**

## Suggested repository layout by v0.2

```text
refscope/
├── src/
│   ├── cli/
│   ├── capture/
│   ├── symbols/
│   ├── model/
│   ├── correlate/
│   ├── diff/
│   ├── diagnose/
│   └── output/
├── bpf/
├── targets/
│   ├── rxrpc.yaml
│   └── ...
├── tests/
│   ├── synthetic/
│   ├── integration/
│   └── regressions/
├── cases/
│   └── <real-kernel-bug>/
└── docs/
```

## Stop/go checkpoints

### Gate A — after v0.1
Continue only if:
- the same failing run produces a stable diagnosis;
- the tool identifies the correct divergence in at least 5 deliberately injected bugs;
- it is already more useful than reading a raw event stream.

### Gate B — after v0.3
Continue only if at least one of these is true:
- it materially shortened diagnosis of a real kernel bug;
- it found a root cause you had not already identified manually;
- another kernel developer says the output is useful enough that they would run it.

If none is true after several appropriate bugs: **pivot**.

### Gate C — before v1.0
Do not call it stable unless:
- at least 5 real bugs have been diagnosed with meaningful assistance from RefScope;
- at least 2–3 fixes have reached upstream or maintainer trees;
- at least one person other than you has successfully used the tool;
- the stable output/config schemas are documented and tested.

## Recommended strategy

Treat **v0.3 as the real objective**. Do not spend six months polishing infrastructure before proving one real Linux bug.

The fastest credible path to attention is:

```text
v0.0.1 → v0.0.2 → v0.1
                  ↓
            real syzbot bug
                  ↓
              upstream fix
```

If that loop works, continue toward v0.5+. If it does not, the project has given you enough evidence to pivot without wasting a year.
