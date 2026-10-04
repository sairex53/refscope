# Research sources behind the roadmap

These are the main public references used to avoid building a project around a false novelty claim.

## Existing lifetime/reference debugging

### Linux debugobjects
Linux kernel documentation: "The object-lifetime debugging infrastructure"
https://kernel.org/doc/html/next/core-api/debug-objects.html

### Linux ref_tracker
Current kernel source:
https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/master/lib/ref_tracker.c

Header/source view:
https://codebrowser.dev/linux/linux/include/linux/ref_tracker.h.html

Example networking integration:
https://github.com/torvalds/linux/blob/master/net/core/net_namespace.c

### retsnoop
Andrii Nakryiko:
https://github.com/anakryiko/retsnoop

A BPF-based non-invasive mass-tracer for Linux kernel internals, including arguments/returns/call stacks and error-focused tracing.

## Current reference-count observability work

### `refcount_final_put` v5 patch series
Linux kernel mailing list, 2026-08-13:
https://lists.openwall.net/linux-kernel/2026/08/13/200

The series motivates a tracepoint for the final reference release because this information materially helps UAF debugging and broad live tracing is expensive.

This roadmap does not assume the patch is merged.

## Static/reference-count bug research

### DrvHorn
"Automatic Detection of Reference Counting Bugs in Linux Kernel Drivers", 2026:
https://arxiv.org/abs/2605.13246

The paper reports 545 true bugs, 424 previously unknown, with 45 fixes merged.

This is important evidence that "automatic refcount bug detection" itself is not a novel claim.

## Syzkaller/syzbot

### syzbot behavior and bisection
https://github.com/google/syzkaller/blob/master/docs/syzbot.md

### reproducing crashes
https://github.com/google/syzkaller/blob/master/docs/reproducing_crashes.md

Syzbot already provides much of the bug discovery/reproduction/bisection pipeline. RefScope should focus on the human-heavy lifetime root-cause step.

## Adjacent automated root-cause/security systems

### SyzScope
https://github.com/plummm/SyzScope

Focuses on uncovering higher-risk security impacts from fuzzer-exposed kernel bugs.

### AutoKFL
"Linux Kernel Fault Localization via ReAct-Based Multi-Agent Framework with Dynamic Crash Reproduction", 2026:
https://www.mdpi.com/1424-8220/26/13/4129

Evidence that broad automated kernel fault localization is an active/crowded direction.

### syzkaller AI triage discussion
https://github.com/google/syzkaller/issues/7734

Shows active interest in AI-assisted triage in the syzkaller ecosystem.

## sched_ext alternative

### Linux sched_ext documentation
https://github.com/torvalds/linux/blob/master/Documentation/scheduler/sched-ext.rst

### sched-ext/scx
https://github.com/sched-ext/scx

### Meta production case study
"Modernizing the Meta Ads Service With an Open-Source Kernel Scheduler", 2026-07-13:
https://engineering.fb.com/2026/07/13/ml-applications/modernizing-the-meta-ads-service-with-an-open-source-kernel-scheduler/

Meta reports a 28% reduction in a measured p99 ads-retrieval stage, 3.28 MW fleet power savings, and additional follow-on improvements from a workload-specific sched_ext policy.

### Oracle bpftune
https://github.com/oracle/bpftune

Existing BPF-driven Linux auto-tuning project. This matters because a generic "BPF autotuner" is also not a new concept.

## Interpretation

Public research cannot prove that no company has private internal tooling similar to RefScope.

The defensible claim is narrower:

> The public ecosystem contains detectors, tracers, explicit reference trackers, static refcount analyzers, and generic fault-localization work; a practical runtime tool centered on object/reference provenance plus good/bad lifetime differential diagnosis is still sufficiently distinct to justify a bounded experiment.

The project should be abandoned or repositioned if later research finds a public tool that already provides the same workflow better.
