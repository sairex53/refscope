#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "refscope/event.h"
char LICENSE[] SEC("license") = "GPL";
const volatile __u64 target_ip = 0;
const volatile __u32 object_arg = 0;
const volatile __s32 reason_arg = -1;
const volatile __u16 target_id = 0;
const volatile __u8 event_type = 0;
const volatile bool stacks_enabled = true;
const volatile __u32 filter_pid = 0, filter_tid = 0;
const volatile __u64 filter_object = 0;
const volatile char filter_comm[16] = {};
const volatile bool filter_cpus = false;
const volatile __u8 cpu_allowed[RS_MAX_CPUS] = {};
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 24); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct rs_stats); } stats SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_STACK_TRACE); __uint(max_entries, 16384);
    __type(key, __u32); __type(value, __u64[RS_STACK_DEPTH]); } stacks SEC(".maps");
static __always_inline int emit(void *ctx, __u64 obj, __u64 reason, __u64 ip)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 cpu = bpf_get_smp_processor_id(), zero = 0;
    char comm[16];
    if (filter_pid && (id >> 32) != filter_pid) return 0;
    if (filter_tid && (__u32)id != filter_tid) return 0;
    if (filter_object && obj != filter_object) return 0;
    if (filter_cpus && (cpu >= RS_MAX_CPUS || !cpu_allowed[cpu])) return 0;
    bpf_get_current_comm(comm, sizeof(comm));
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (filter_comm[0] && comm[i] != filter_comm[i]) return 0;
    }
    struct rs_stats *s = bpf_map_lookup_elem(&stats, &zero);
    if (!s)
        return 0;

    /*
     * attempted counts every post-filter probe invocation, including
     * invocations rejected by the same-CPU reentrancy guard.
     */
    __sync_fetch_and_add(&s->attempted, 1);

    /*
     * Per-CPU map + nonblocking atomic guard:
     * never spin in interrupt/NMI context.  A nested invocation is
     * explicitly accounted and returns immediately.
     */
    if (__sync_val_compare_and_swap(&s->busy, 0, 1) != 0) {
        __sync_fetch_and_add(&s->nested_dropped, 1);
        return 0;
    }

    /*
     * Only the guard owner issues sequence/timestamp metadata.
     * The guard remains held through ring-buffer publication, so accepted
     * events from this CPU cannot publish out of sequence.
     */
    __u64 seq = s->sequence + 1;
    s->sequence = seq;
    __u64 ts_ns = bpf_ktime_get_ns();

    struct rs_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&s->ring_dropped, 1);
        __sync_val_compare_and_swap(&s->busy, 1, 0);
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns = ts_ns;
    e->sequence = seq;
    e->obj = obj;
    e->aux = reason;
    e->ip = ip;
    e->pid = id >> 32;
    e->tid = id;
    e->cpu = cpu;
    e->schema_version = RS_SCHEMA_VERSION;
    e->target_id = target_id;
    e->type = event_type;
    e->flags = reason_arg >= 0 ? 1 : 0;
    __builtin_memcpy(e->comm, comm, sizeof(comm));

    e->stack_id = -1;
    if (stacks_enabled) {
        e->stack_id = bpf_get_stackid(ctx, &stacks, 0);
        if (e->stack_id < 0)
            __sync_fetch_and_add(&s->stack_errors, 1);
    }

    bpf_ringbuf_submit(e, 0);

    /*
     * Release only after publication.  Use an atomic operation rather than
     * a plain store so nested execution cannot observe a torn RMW state.
     */
    __sync_val_compare_and_swap(&s->busy, 1, 0);
    return 0;
}
static __always_inline __u64 arg(struct pt_regs *ctx, __u32 n)
{
    switch (n) {
    case 0: return PT_REGS_PARM1_CORE(ctx);
    case 1: return PT_REGS_PARM2_CORE(ctx);
    case 2: return PT_REGS_PARM3_CORE(ctx);
    case 3: return PT_REGS_PARM4_CORE(ctx);
    case 4: return PT_REGS_PARM5_CORE(ctx);
    default: return 0;
    }
}
SEC("kprobe") int capture_kprobe(struct pt_regs *ctx)
{
    return emit(ctx, arg(ctx, object_arg), reason_arg < 0 ? 0 : arg(ctx, reason_arg), PT_REGS_IP_CORE(ctx));
}
SEC("fentry") int capture_fentry(__u64 *ctx)
{
    return emit(ctx, ctx[object_arg], reason_arg < 0 ? 0 : ctx[reason_arg], target_ip);
}

SEC("fexit") int capability_fexit(__u64 *ctx)
{ (void)ctx; return 0; }
