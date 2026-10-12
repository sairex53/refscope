# RefScope

RefScope is an experimental Linux kernel tool for investigating object lifetime and reference-counting bugs. It captures events from kernel functions selected by the user, turns saved captures into per-object timelines, and compares separate runs to suggest places where reference behavior differs.

It is a prototype for kernel developers and researchers who are comfortable with Linux tracing and kernel builds. It is not a general-purpose debugger, and its diagnosis output is a set of hypotheses for human review.

## What it does

- **Capture selected kernel events.** An eBPF program records calls to explicitly selected acquire, release, create, and free functions. A target can identify the object pointer and an optional reason value from function arguments. Events include per-CPU sequence numbers, task and CPU information, timestamps, and optional kernel stacks.
- **Track capture quality.** The trace output includes counters for attempted, captured, and dropped events, stack errors, and other available loss information. Unknown counters stay unknown instead of being reported as zero.
- **Build an offline object timeline.** The timeline groups events by object address and generation. If recording starts after an object's creation, its origin stays marked as partial. GET and PUT counts are observations; they are never presented as the kernel's actual reference count.
- **Inspect candidate targets.** Offline source and BTF metadata can be used to suggest acquire and release functions and write an editable target description. Suggestions are not ground truth and are never attached automatically.
- **Compare saved runs.** The diagnosis prototype aligns semantic operations from labeled baseline and failing runs, then ranks possible missing releases, extra releases, transfer differences, and error-path differences. Reports include evidence and confidence limits.
- **Import a syzbot case.** The syzbot intake command can prepare a local case bundle from a bug report or local report file. Intake does not run a reproducer or claim that RefScope has diagnosed the bug.

## Current state

The current source contains the v0.0.1 capture core, the v0.0.2 offline timeline, v0.2 offline target provenance and discovery, and a v0.1 differential-diagnosis prototype. These labels describe development milestones; there is no stable release or tagged version.

The automated tests pass on the current Fedora ARM64 development environment. Diagnosis accuracy tests use synthetic fixtures: the current suite covers eight injected scenarios with ten repetitions per scenario and reports 100% top-three accuracy on those fixtures. This is not a measurement of accuracy on real kernel subsystems. The v0.1 release gate remains open until a known real subsystem divergence is reproduced and analyzed. True NMI reentrancy has not been verified.

A static case bundle for a public syzbot keyrings use-after-free report is included under cases/. It has not been compiled or executed. It is a research input, not a RefScope diagnosis or a reproduction result.

See STATUS.md for the milestone status and docs/roadmap/ for the planned version sequence.

## Build requirements

RefScope currently supports Linux x86_64 and AArch64. Building the capture binary requires:

- a C compiler and make;
- clang with the BPF target and bpftool;
- libbpf, libelf, and pkg-config development files;
- Python 3;
- kernel BTF at /sys/kernel/btf/vmlinux for the running kernel.

Matching kernel development headers and dwarves/pahole are needed for the optional synthetic test module. Optional source-line lookup uses libdw and matching kernel debug information.

## Build and test

From the repository root:

    make
    make test

The build writes generated files to build/. The test suite exercises the CLI, JSON output, source lookup fallback, timeline and bundle logic, target inspection, provenance adapters, diagnosis rules, and syzbot intake.

The trace operation normally requires root and a kernel with the required BPF tracing support. Start with a dry run to check a target:

    sudo ./build/refscope trace --get 'foo_get:obj=arg0' --put 'foo_put:obj=arg0' --dry-run

Replace foo_get and foo_put with real, non-inlined functions in the target kernel. A dry run checks symbol and argument information where available; it cannot guarantee that a later probe attach will succeed.

## Capture example

    sudo ./build/refscope trace \
      --get 'foo_get:obj=arg0,reason=arg1' \
      --put 'foo_put:obj=arg0,reason=arg1' \
      --duration 10s --format jsonl > capture.jsonl

Start the workload after RefScope prints its ready marker. Stop with Ctrl-C or let the duration expire. The JSONL stream contains event, stack, and summary records.

Capture accepts up to 32 explicitly selected functions. Object and reason values are raw argument values; RefScope does not dereference kernel objects. The default backend prefers fentry and may fall back to kprobe after an attach failure when the target is not blacklisted. The backend can also be selected explicitly.

Capture output can contain kernel addresses, symbols, process names, and stack information. Treat it as potentially sensitive and keep real run data outside the Git repository.

## Offline commands

Render an event stream as a timeline:

    ./build/refscope timeline --input capture.jsonl --format text
    ./build/refscope timeline --input capture.jsonl --format json --object 0xffff888012340000

Inspect likely operations for a type and save a candidate target file for review:

    ./build/refscope inspect-target --type 'struct foo' --kernel-tree /path/to/linux --write-target targets/foo.yaml

Compare previously saved, labeled bundles:

    ./build/refscope diagnose runs/ --format text
    ./build/refscope diagnose runs/ --format json

Prepare a local syzbot case bundle:

    ./build/refscope syzbot d47fcea929219ef53b5b0f700f2102bed78b6202

The timeline and diagnosis commands are offline: they operate on saved input and do not attach kernel probes.

## How to read the results

- A timeline identity is an object address plus a generation. Ambiguous address reuse starts a new partial generation rather than silently merging lifetimes.
- Observed GET minus PUT is only an observed operation balance. It does not prove the value of refcount_t or identify which owner holds a reference.
- Diagnosis confidence describes the available evidence. Even a high-ranked candidate is not proof of root cause.
- Dropped events, incomplete captures, ambiguous generations, or missing stacks reduce the strength of a conclusion.
- Discovery produces editable suggestions. Only reviewed operations explicitly supplied by the user can become capture targets.

## Optional synthetic kernel module

tests/synthetic/ provides a development fixture for a disposable VM or test machine. It models explicit object-lifetime boundaries and does not allocate or free kernel memory. Build it with the matching kernel headers; module-btf additionally uses pahole. Do not load the fixture on a production system.

## Project structure

- bpf/ and src/capture/: eBPF event collection and the C capture CLI.
- src/timeline/: offline timeline and bundle handling.
- src/provenance/: source/BTF inspection and target suggestions.
- src/diagnosis/: offline run alignment and candidate ranking.
- src/syzbot/: case intake and report preparation.
- include/refscope/: event, target, and source interfaces.
- tests/: unit, fixture, and integration tests.
- docs/design/ and docs/roadmap/: design contracts and milestone plans.
- cases/: a statically reviewed public syzbot input bundle.

## Limitations

RefScope does not automatically discover every reference operation, prove ownership, infer the actual kernel reference count from GET/PUT events, or provide a verified root cause for a real kernel bug. It has not completed validation against a reproducible known real-subsystem divergence. Use its reports as investigation aids and verify every proposed explanation against source and controlled runs.


## License

RefScope is licensed under the MIT License.
See [LICENSE](LICENSE) for details.
