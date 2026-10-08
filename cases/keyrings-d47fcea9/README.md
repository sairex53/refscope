# Keyrings `key_put` case bundle

This directory archives the public syzbot case `d47fcea929219ef53b5b0f700f2102bed78b6202` for **static review only**.
No reproducer has been compiled or executed; no kernel, VM, or module was started.

## Provenance

- Title: KASAN slab-use-after-free read in `key_put`.
- Report snapshot: upstream Linux `6.12.0-syzkaller`, commit `adc218676eef25575469234709c2d87185ca223a`, x86_64.
- Compiler: `gcc (Debian 12.2.0-14)` as recorded by the report/config.
- Report config: `input/config`; provenance and hashes for every downloaded artifact are in `input/source-manifest.json`.
- Cause bisection points to `9578e327b2b4935a25d49e3891b8fcca9b6c10c6`.
- Fix `75845c6c1a64483e9985302793dbf0dfa5f71e32`, parent `88d324e69ea9f3ae1c1905ea75d717c08bdb8e15`. It changes `include/linux/key.h`, `security/keys/gc.c`, and `security/keys/key.c`: `key_put` sets `KEY_FLAG_FINAL_PUT`, and the key garbage collector consumes that flag rather than reading the reference counter after final put. The public report and fix explanation agree on the lifetime defect.

The report's `.config` is for x86_64 and **does not** enable `CONFIG_KPROBES` or `CONFIG_DEBUG_INFO_BTF`; it does enable `CONFIG_KEYS`, `CONFIG_ENCRYPTED_KEYS`, generic KASAN, `CONFIG_DEBUG_INFO`, BPF syscall/events, and FTRACE. This is the upstream reproducer configuration, not a RefScope-ready configuration. The report page links a vmlinux asset, but its build ID is not in this case metadata because the ELF was not downloaded/inspected (`vmlinux_build_id: null`).

## Static reproducer review (not executed)

`repro.c` uses libc/pthreads and Linux syscall headers; it has no inline assembly or literal syscall-number table. `__NR_*`/`SYS_futex` are selected by target headers; the checked AArch64 asm-generic headers define the key syscall and futex. Source-level ARM64 compilation is plausible but unverified. The C file still contains x86-only `/dev/cpu/#/msr` probing and other environment-dependent calls; unsupported calls can fail, and portability/equivalent triggering is not established. Fixed low user mappings, repeated forks/threads, `SIGKILL` cleanup, `oom_score_adj`, and a FUSE-abort fallback make it inappropriate to run on the Fedora host.

`repro.syz` specifies `threaded=true`, `repeat=true`, `procs=5`, and no syzkaller sandbox. It includes `add_key` for an encrypted key, plus MSR, cgroup, networking, mmap and futex operations. The MSR device and parts of the syscall mix are x86/environment specific; an ARM64 syzkaller reproducer must be generated/minimized and independently reviewed, not assumed equivalent. For faithful privilege parity, any future execution belongs as root inside a disposable guest; the minimum privilege required by a reduced key-only C reproducer has not been established.

## Build/config facts

The affected full commit is verified as `adc218676eef25575469234709c2d87185ca223a` from the syzbot crash row. Upstream Git reports the fix commit `75845c6c1a64483e9985302793dbf0dfa5f71e32` exists; its parent is `88d324e69ea9f3ae1c1905ea75d717c08bdb8e15`, and compare metadata places the affected commit in that ancestry. The fix changes the exact reported `key_put`/GC path. Source is obtainable from the public upstream Git tree at the affected commit; no source tree was cloned or built here.

For a same-source ARM64 experiment, start with that exact source commit and an ARM64 `defconfig`, then explicitly set `CONFIG_KEYS=y`, `CONFIG_ENCRYPTED_KEYS=y`, `CONFIG_KASAN=y`, `CONFIG_KASAN_GENERIC=y`, `CONFIG_DEBUG_INFO=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_EVENTS=y`, `CONFIG_FTRACE=y`, `CONFIG_FUNCTION_TRACER=y`, and `CONFIG_KPROBES=y` for RefScope. For QEMU `virt` with initramfs/virtio root storage also enable `CONFIG_ARM64=y`, `CONFIG_SERIAL_AMBA_PL011=y`, `CONFIG_SERIAL_AMBA_PL011_CONSOLE=y`, `CONFIG_BLK_DEV_INITRD=y`, `CONFIG_DEVTMPFS=y`, `CONFIG_DEVTMPFS_MOUNT=y`, `CONFIG_TMPFS=y`, `CONFIG_VIRTIO=y`, `CONFIG_VIRTIO_MMIO=y`, `CONFIG_VIRTIO_BLK=y`, `CONFIG_EXT4_FS=y`, and `CONFIG_BINFMT_ELF=y`. Keep the same resulting config/compiler for bad and fixed builds. BTF requires compatible pahole; `CONFIG_DEBUG_INFO_BTF_MODULES` is only needed if selected targets are modules. This is an ARM64 variant, **not** the exact x86 report kernel/config, and may not reproduce.

## Isolated VM plan — proposed, not created

Current host recheck: Fedora ARM64, 4 logical CPUs, cgroup CPU set `0-3`, 4 GiB RAM, about 0.9 GiB available at inspection, 8 GiB swap (about 7.4 GiB free), and 34 GiB free disk. `qemu-system-aarch64` 10.2.2 is installed, but `/dev/kvm` is absent; execution would use slow TCG emulation. No x86_64 system emulator is installed. Do not start this build/guest with current memory headroom.

Proposed safe ARM64 guest on a suitably provisioned ARM64 host: 2 vCPU, 6 GiB RAM, 40 GiB qcow2 disk with a read-only base plus a fresh writable overlay per kernel/run; reserve at least 50 GiB free host storage for source, build trees, logs, and overlays. Current Fedora has 4 GiB total RAM (~0.9 GiB available) and 34 GiB free disk, so it cannot safely host this plan. These are planning allocations, not tested minima; smaller allocation is not claimed sufficient for KASAN kernel compilation.

1. Fetch source at `adc218676eef25575469234709c2d87185ca223a`; build the bad image. Build a second image at `75845c6c1a64483e9985302793dbf0dfa5f71e32` with identical ARM64 config/compiler. Preserve `.config`, compiler version, source hashes, and each `vmlinux` build ID. The two commits are the proposed bad/good pair; no outcome is assumed. Source/build can be obtained, but this host currently lacks safe memory headroom; prefer a larger builder/host.
2. Boot `Image` with QEMU `virt`, PL011 serial, virtio-blk, initramfs, and `-net none`. Kernel config needs the options listed above. Use a minimal initramfs for boot, plus a guest ext4 root disk containing a compatible ARM64 toolchain/build dependencies, kernel source/build outputs, libc/pthreads, and reviewed tools; mount `/proc`, `/sys`, `/dev`, and `/tmp`. Use KASAN boot parameters and retain serial console output.
3. Put the source reproducers on a read-only data image (or bake them into the initramfs); do not use 9p/virtiofs host sharing. Copy into guest tmpfs. Do not pass host devices, block devices, USB, or network interfaces. Use a per-run qcow2 overlay and discard it after archival; export only serial logs and result metadata.
4. For later rate measurement, predeclare N independent attempts and a timeout. Record attempts, KASAN signatures matching `key_put`, non-crashes, timeouts, and time-to-failure; report `M/N` and median time. Repeat the same procedure on bad and fixed builds. This bundle contains no reproduction-rate claim.
5. Run RefScope only inside the guest after adding BTF/kprobes/ftrace options above, as root, with explicitly selected key targets. Keep probe configuration and capture quality in each run record. Never attach probes or run either reproducer on the Fedora host.

## Difference from current Fedora

The current Fedora kernel `7.2.6-200.fc44.aarch64` is neither affected commit `adc218676eef25575469234709c2d87185ca223a` nor fixed commit `75845c6c1a64483e9985302793dbf0dfa5f71e32`. Its BTF is not a substitute for the case kernel's symbols. No matching case `vmlinux` was downloaded. No source, kernel, RefScope production code, or existing VM was modified.
