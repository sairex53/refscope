#ifndef REFSCOPE_EVENT_H
#define REFSCOPE_EVENT_H
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif
#define RS_SCHEMA_VERSION 1
#define RS_STACK_DEPTH 16
#define RS_MAX_CPUS 4096
enum rs_type { RS_GET, RS_PUT, RS_CREATE, RS_FREE, RS_CALL_RETURN };
struct rs_event {
    __u64 ts_ns, sequence, obj, ip, aux;
    __u32 pid, tid, cpu;
    __s32 stack_id;
    __u16 schema_version, target_id;
    __u8 type, flags;
    char comm[16];
    __u8 reserved[2];
};
struct rs_stats {
    __u64 attempted;
    __u64 ring_dropped;
    __u64 nested_dropped;
    __u64 stack_errors;
    __u64 sequence;
    __u64 busy;
};
#endif
