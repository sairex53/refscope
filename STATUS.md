# RefScope status

RefScope is an experimental prototype. Version labels below are development milestones; no stable release is tagged.

## Implemented

| Area | Status |
| --- | --- |
| Kernel event capture | Implemented for manually selected targets with eBPF, fentry/kprobe backends, filters, stacks, JSONL output, and capture-loss accounting. |
| Offline object timeline (v0.0.2) | Implemented with object generations, partial origins, bundle output, and separate observed-balance and actual-refcount fields. |
| Target provenance and discovery (v0.2) | Implemented as offline source/BTF inspection and editable candidate target descriptions. Candidates are not automatically attached. |
| Differential diagnosis (v0.1) | Implemented as an offline prototype for comparing saved runs and ranking evidence-backed candidates. |
| syzbot intake | Implemented for preparing local case bundles from reports. It does not reproduce bugs or perform end-to-end diagnosis. |

## Validation and open gates

- The repository test suite passes with make test in the Fedora ARM64 development environment.
- Diagnosis metrics are fixture-only: eight synthetic injected scenarios, ten repeats each, with 100% top-three accuracy in the current test suite. This result does not establish accuracy on real kernel subsystems.
- The v0.1 real-world gate is open. No reproducible known subsystem divergence has been validated end to end.
- A public syzbot keyrings use-after-free report is archived under cases/ for static review. Its reproducer has not been executed.
- Same-CPU hard-IRQ self-IPI reentry has been tested separately; true NMI reentrancy remains unverified.
- Runtime probe availability depends on the running kernel configuration, BTF, symbols, and permissions.

## Safety and interpretation

Capture only targets explicitly configured by the user. Discovery output requires review. RefScope does not dereference object pointers, and observed GET/PUT balance is not an actual kernel refcount. Diagnosis reports rank hypotheses; they do not prove root cause. Captures may contain addresses, symbols, process names, and stack information, so keep real run data private.
