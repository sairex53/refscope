# Development storage and cleanup policy

RefScope is being developed on Fedora 44 ARM64. This inventory is designed for repeated use; it does not infer that a large or old directory is disposable. Run the live report with:

    make storage

The report is read-only. Parent and child directory sizes overlap and must not be added together. It records project data, retained evidence/backups, installed shared build dependencies, Podman container/storage summaries, and selected sibling projects.

## Classification

| Class | Meaning and policy |
| --- | --- |
| PERMANENT | Source, Git history, reviewed case inputs, saved run evidence, backups, and the progress journal. Keep unless a separately reviewed deletion is explicitly requested. |
| REBUILDABLE | The repository-local build/ output and Python bytecode caches under src/ and tests/. These can be recreated, but the cleanup script still requires explicit interactive confirmation. |
| TEMPORARY | No retained RefScope run or case data is automatically classified as disposable. Temporary output must be identified by its exact run manifest and reviewed before removal. |
| EXTERNAL/SHARED | System packages, Podman images/containers, and separate project copies. They can be used by other work; this tool never removes or prunes them. |
| UNKNOWN | Data-root entries whose owner/lifecycle is not established, global caches, and other unreviewed paths. Preserve them. |

The case bundles under cases/ and all paths under refscope-data/runs/ and refscope-data/backups/ are retained inputs/evidence. A large size or age does not make them temporary. The progress journal itself is retained. The named containers strace-349-build and curl-23479-review are shared/external and are not cleanup candidates.

## Commands and safety boundaries

    make storage

Print a read-only inventory.

    make storage-clean

Show a cleanup plan only. This is a dry run and deletes nothing.

    ./scripts/dev-storage.sh clean-rebuildables --apply

The applying form refuses non-interactive input, checks that the Makefile clean recipe still removes only the exact project build/ directory, rejects a symlinked build directory, checks for active RefScope/capture/matrix/lifecycle work before and after confirmation, and requires the exact phrase CLEAN REFSCOPE REBUILDABLES. It then removes only build/ and Python __pycache__ directories below src/ and tests/.

It never runs package-manager removal, Podman stop/prune, git clean, or deletion of cases, Git history, logs, saved results, backups, sibling projects, the home cache, or unknown data. Review the printed paths before confirming. If ownership or use is uncertain, do not clean.

## Baseline at recovery audit

The live Fedora root filesystem was 98 GiB total with about 40 GiB available at the initial check. A later check reported 60 GiB used and 38 GiB available; that increase was not attributed to a RefScope operation and should be rechecked rather than assumed to be reclaimable. The working repository was about 7.9 MiB total (.git about 716 KiB, build/ 4.6 MiB, cases/ 356 KiB, src/ 700 KiB, tests/ 1.4 MiB). These rows overlap with the repository total.

The shared user cache is at least 5.3 GiB, but its size is partial: du could not read /home/angel/.cache/gvisor-bazel-2490/cc-overlay/work/work (Permission denied). It is UNKNOWN/shared, not a RefScope cleanup target. The live script marks partial sizes with an asterisk and emits the reason instead of silently presenting them as complete.

The data root included about 2.5 MiB of backups and a small retained run-evidence tree. Other data-root directories included buildroot (about 81 MiB), kernel-evidence (55 MiB), syzkaller (464 MiB), and tmp (64 MiB); they are classified UNKNOWN until their precise ownership and lifecycle are reviewed. They are not managed by this cleanup command.

The two running Podman containers had reported writable sizes of about 357 MiB and 414 MiB. Their image/storage layers are shared. Installed GCC, Clang, Make, bpftool, libbpf and elfutils packages already satisfied the project's build needs; no dependency was installed for this change. RPM package SIZE values are included in the live inventory and should not be treated as exact reclaimable space.

## Dependence lifecycle

The binary and generated BPF artifacts are rebuilt with the existing Makefile into build/. Source, tests, Git history, case inputs, and evidence are not build caches. System compiler/BPF/libdw packages remain shared host dependencies; do not remove them via autoremove as part of RefScope cleanup. The v0.3 keyrings kernel experiment is on a separate Debian VM and is outside the Fedora project's cleanup whitelist.
