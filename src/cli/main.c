#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <stddef.h>
#include "refscope/source.h"
#include "refscope/event.h"
#include "refscope/target.h"
#include "trace.skel.h"
#define MAX_TARGETS 32
static struct rs_target targets[MAX_TARGETS];
static struct trace_bpf *probes[MAX_TARGETS];
static struct bpf_link *links[MAX_TARGETS];
static unsigned ntargets;
static bool json, no_stacks, dry, doctor;
static const char *vmlinux;
static bool selected_fentry[MAX_TARGETS];
static unsigned long long ordering_errors, recursion_misses, kprobe_misses;
static bool recursion_known = true, kprobe_misses_known = true, miss_snapshot;
static __u64 last_seq[RS_MAX_CPUS], last_ts[RS_MAX_CPUS];
static const char *backend = "auto";
static unsigned pid_filter, tid_filter, ring_size = 1 << 24;
static unsigned char cpus[RS_MAX_CPUS];
static bool cpu_filter;
static unsigned long long object_filter;
static char comm_filter[16];
static double duration = 10;
static volatile sig_atomic_t stopping;
static unsigned long long captured;
static unsigned long long stack_lookup_errors;
static bool seen_stacks[16384];
struct symbol { unsigned long long address; char *name; char *module; };
static struct symbol *symbols;
static size_t nsymbols;
static void signal_stop(int sig) { (void)sig; stopping = 1; }
static void fail(const char *message) { fprintf(stderr, "refscope: %s\n", message); exit(2); }
static unsigned long long number(const char *s, unsigned long long max)
{
    char *end; errno = 0;
    if (*s < '0' || *s > '9') fail("expected a nonnegative integer");
    unsigned long long value = strtoull(s, &end, 0);
    if (errno || *end || value > max) fail("integer out of range or malformed");
    return value;
}
static void usage(void)
{
    puts("RefScope v0.0.1-dev\nUsage: refscope trace --get 'fn:obj=arg0[,reason=arg1]' --put 'fn:obj=arg0'\n"
         "  --create SPEC --free SPEC --duration 10s --format text|jsonl\n"
         "  --pid PID --tid TID --comm NAME --object ADDRESS --cpu 0,1-3\n"
         "  --dry-run --no-stacks --backend auto|fentry|kprobe --ring-size BYTES\n"
         "  --vmlinux PATH; refscope doctor [target options]\n"
         "  refscope inspect-target --type 'struct foo' [--kernel-tree PATH] [--vmlinux PATH] [--write-target PATH]\n"
         "  refscope timeline --input run/events.jsonl --format text|json\n"
         "  refscope diagnose runs/ [--format text|json]\n"
         "  refscope syzbot <bug-id-or-local-report> [--kernel-tree PATH] [--vmlinux PATH]");
}
static void parse_cpus(const char *s)
{
    char *copy = strdup(s), *rest = copy, *part;
    if (!copy) fail("out of memory");
    while ((part = strsep(&rest, ","))) {
        char *dash = strchr(part, '-');
        if (dash) *dash++ = 0;
        unsigned first = number(part, RS_MAX_CPUS - 1), last = dash ? number(dash, RS_MAX_CPUS - 1) : first;
        if (last < first) fail("reversed CPU range");
        for (unsigned i = first; i <= last; i++) cpus[i] = 1;
    }
    free(copy); cpu_filter = true;
}
static int symbol_cmp(const void *a, const void *b)
{
    const struct symbol *x = a, *y = b;
    return (x->address > y->address) - (x->address < y->address);
}
static void load_symbols(void)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    char line[512], name[256], mod[128], type; unsigned long long address;
    if (!f) fail("cannot read /proc/kallsyms");
    size_t capacity = 0;
    while (fgets(line, sizeof(line), f)) {
        int fields = sscanf(line, "%llx %c %255s %127s", &address, &type, name, mod);
        if (fields < 3 || !strchr("tTwW", type)) continue;
        if (nsymbols == capacity) {
            capacity = capacity ? capacity * 2 : 4096;
            void *p = realloc(symbols, capacity * sizeof(*symbols));
            if (!p) fail("out of memory");
            symbols = p;
        }
        char *copy = strdup(name);
        if (!copy) {
            fclose(f);
            fail("out of memory while loading kernel symbols");
        }
        char *module_name = NULL;
        if (fields == 4 && mod[0] == '[' && mod[strlen(mod)-1] == ']') {
            mod[strlen(mod)-1] = 0;
            module_name = strdup(mod+1);
            if (!module_name) fail("out of memory while loading module names");
        }
        symbols[nsymbols++] = (struct symbol){address, copy, module_name};
    }
    if (ferror(f)) {
        fclose(f);
        fail("error while reading /proc/kallsyms");
    }
    fclose(f);
    qsort(symbols, nsymbols, sizeof(*symbols), symbol_cmp);
}
static const char *symbolize(unsigned long long ip, unsigned long long *offset)
{
    size_t lo = 0, hi = nsymbols;
    while (lo < hi) { size_t m = lo + (hi - lo) / 2; if (symbols[m].address <= ip) lo = m + 1; else hi = m; }
    if (!lo || !symbols[lo-1].address) { *offset = 0; return "unknown"; }
    *offset = ip - symbols[lo-1].address;
    return symbols[lo-1].name;
}
static size_t valid_utf8_length(const unsigned char *s, size_t remaining)
{
    if (!remaining)
        return 0;

    unsigned char c = s[0];

    if (c < 0x80)
        return 1;

    if (c >= 0xc2 && c <= 0xdf) {
        if (remaining >= 2 &&
            s[1] >= 0x80 && s[1] <= 0xbf)
            return 2;
        return 0;
    }

    if (c == 0xe0) {
        if (remaining >= 3 &&
            s[1] >= 0xa0 && s[1] <= 0xbf &&
            s[2] >= 0x80 && s[2] <= 0xbf)
            return 3;
        return 0;
    }

    if ((c >= 0xe1 && c <= 0xec) ||
        (c >= 0xee && c <= 0xef)) {
        if (remaining >= 3 &&
            s[1] >= 0x80 && s[1] <= 0xbf &&
            s[2] >= 0x80 && s[2] <= 0xbf)
            return 3;
        return 0;
    }

    if (c == 0xed) {
        if (remaining >= 3 &&
            s[1] >= 0x80 && s[1] <= 0x9f &&
            s[2] >= 0x80 && s[2] <= 0xbf)
            return 3;
        return 0;
    }

    if (c == 0xf0) {
        if (remaining >= 4 &&
            s[1] >= 0x90 && s[1] <= 0xbf &&
            s[2] >= 0x80 && s[2] <= 0xbf &&
            s[3] >= 0x80 && s[3] <= 0xbf)
            return 4;
        return 0;
    }

    if (c >= 0xf1 && c <= 0xf3) {
        if (remaining >= 4 &&
            s[1] >= 0x80 && s[1] <= 0xbf &&
            s[2] >= 0x80 && s[2] <= 0xbf &&
            s[3] >= 0x80 && s[3] <= 0xbf)
            return 4;
        return 0;
    }

    if (c == 0xf4) {
        if (remaining >= 4 &&
            s[1] >= 0x80 && s[1] <= 0x8f &&
            s[2] >= 0x80 && s[2] <= 0xbf &&
            s[3] >= 0x80 && s[3] <= 0xbf)
            return 4;
    }

    return 0;
}

static void json_string(const char *s, size_t max)
{
    putchar('"');

    for (size_t i = 0; i < max && s[i];) {
        unsigned char c = (unsigned char)s[i];

        if (c == '"' || c == '\\') {
            printf("\\%c", c);
            i++;
        } else if (c < 0x20 || c == 0x7f) {
            printf("\\u%04x", c);
            i++;
        } else if (c < 0x80) {
            putchar(c);
            i++;
        } else {
            size_t length = valid_utf8_length(
                (const unsigned char *)s + i,
                max - i
            );

            if (!length) {
                /*
                 * Preserve JSON validity even when kernel/user supplied
                 * strings contain arbitrary non-UTF-8 bytes.
                 */
                printf("\\u%04x", c);
                i++;
                continue;
            }

            fwrite(s + i, 1, length, stdout);
            i += length;
        }
    }

    putchar('"');
}
static int on_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    const struct rs_event *e = data;
    const char *types[] = {"GET", "PUT", "CREATE", "FREE", "CALL_RETURN"};
    if (size != sizeof(*e) || e->schema_version != RS_SCHEMA_VERSION || e->target_id >= ntargets || e->type > RS_CALL_RETURN) return -EPROTO;
    if (e->cpu >= RS_MAX_CPUS || e->stack_id >= 16384) return -EPROTO;
    if (e->sequence <= last_seq[e->cpu] || e->ts_ns < last_ts[e->cpu]) ordering_errors++;
    last_seq[e->cpu] = e->sequence; last_ts[e->cpu] = e->ts_ns;
    if (e->stack_id >= 0) seen_stacks[e->stack_id] = true;
    const char *fn = targets[e->target_id].function;
    if (json) {
        printf("{\"record\":\"event\",\"schema_version\":%u,\"ts_ns\":%llu,\"sequence\":%llu,\"cpu\":%u,\"pid\":%u,\"tid\":%u,\"object\":\"0x%llx\",\"ip\":\"0x%llx\",\"target_id\":%u,\"type\":\"%s\",\"function\":",
               e->schema_version, (unsigned long long)e->ts_ns, (unsigned long long)e->sequence, e->cpu, e->pid, e->tid,
               (unsigned long long)e->obj, (unsigned long long)e->ip, e->target_id, types[e->type]);
        json_string(fn, 128); printf(",\"comm\":"); json_string(e->comm, 16);
        printf(",\"stack_id\":%d,\"reason\":", e->stack_id);
        if (e->flags & 1) printf("%llu", (unsigned long long)e->aux); else printf("null");
        puts("}");
    } else printf("%s %s object=0x%llx ts=%llu cpu=%u seq=%llu pid=%u tid=%u reason=%s%llu stack=%d\n",
                  types[e->type], fn, (unsigned long long)e->obj, (unsigned long long)e->ts_ns, e->cpu,
                  (unsigned long long)e->sequence, e->pid, e->tid, e->flags & 1 ? "" : "unavailable/",
                  (unsigned long long)e->aux, e->stack_id);
    captured++;
    return ferror(stdout) ? -EIO : 0;
}
/* Resolve only after producers are detached and the ring has drained. Stack
 * records can follow events; consumers join them by session-local stack_id. */
static void source_fields(__u64 ip)
{
    const char *file; int line;
    if (!rs_source_lookup(ip, &file, &line)) return;
    if (json) { printf(",\"source_file\":"); json_string(file, strlen(file)); printf(",\"source_line\":%d", line); }
    else printf(" %s:%d", file, line);
}
static void emit_stacks(void)
{
    for (__u32 id = 0; id < 16384; id++) {
        if (!seen_stacks[id]) continue;
        __u64 frames[RS_STACK_DEPTH];
        if (bpf_map_lookup_elem(bpf_map__fd(probes[0]->maps.stacks), &id, frames)) {
            stack_lookup_errors++;
            if (json) printf("{\"record\":\"stack\",\"schema_version\":1,\"stack_id\":%u,\"lookup_failed\":true,\"frames\":[]}\n", id);
            fprintf(stderr, "stack %u lookup failed: %s; event retained, capture incomplete\n", id, strerror(errno));
            continue;
        }
        if (json) printf("{\"record\":\"stack\",\"schema_version\":1,\"stack_id\":%u,\"frames\":[", id);
        else printf("STACK %u", id);
        for (unsigned i = 0; i < RS_STACK_DEPTH && frames[i]; i++) {
            unsigned long long offset; const char *name = symbolize(frames[i], &offset);
            if (json) {
                printf("%s{\"ip\":\"0x%llx\",\"symbol\":", i ? "," : "", (unsigned long long)frames[i]);
                json_string(name, 256); printf(",\"offset\":%llu", offset);
                source_fields(frames[i]); putchar('}');
            } else { printf(" %s+0x%llx", name, offset); source_fields(frames[i]); }
        }
        puts(json ? "]}" : "");
    }
}
static unsigned long long symbol_address(const char *name)
{
    for (size_t i = 0; i < nsymbols; i++) if (!strcmp(name, symbols[i].name)) return symbols[i].address;
    return 0;
}
static int ftrace_listed(const char *function)
{
    FILE *f = fopen("/sys/kernel/tracing/available_filter_functions", "r");
    if (!f) f = fopen("/sys/kernel/debug/tracing/available_filter_functions", "r");
    if (!f) return -1;
    char line[512], name[256]; int found = 0;
    while (fgets(line, sizeof(line), f)) if (sscanf(line, "%255s", name) == 1 && !strcmp(name, function)) { found = 1; break; }
    fclose(f); return found;
}
static int kprobe_blacklisted(const char *function)
{
    FILE *f = fopen("/sys/kernel/debug/kprobes/blacklist", "r");
    if (!f) return -1;
    unsigned long long ip = symbol_address(function), start, end;
    char line[512]; int found = 0;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "%llx-%llx", &start, &end) == 2 && ip >= start && ip < end) { found = 1; break; }
    fclose(f); return found;
}
static int quiet_libbpf(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, fmt, args);
}
static int probe_trampoline(const char *function, bool exit_probe)
{
    struct trace_bpf *s = trace_bpf__open();
    if (!s) return -errno;
    bpf_map__set_max_entries(s->maps.events, sysconf(_SC_PAGESIZE));
    bpf_program__set_autoload(s->progs.capture_kprobe, false);
    bpf_program__set_autoload(s->progs.capture_fentry, !exit_probe);
    bpf_program__set_autoload(s->progs.capability_fexit, exit_probe);
    struct bpf_program *prog = exit_probe ? s->progs.capability_fexit : s->progs.capture_fentry;
    int err = bpf_program__set_attach_target(prog, 0, function);
    if (!err) err = trace_bpf__load(s);
    trace_bpf__destroy(s);
    return err;
}
static const char *supported(int result)
{
    if (result == 1) return "available";
    if (result == 0) return "unsupported (or denied by kernel policy)";
    if (result == -EPERM || result == -EACCES) return "insufficient permissions";
    return "unknown (capability probe failed)";
}
static void report_capabilities(struct btf *base)
{
    struct utsname u; if (uname(&u)) fail("uname failed");
    fprintf(stderr, "architecture: %s; kernel release: %s\nBTF: %s\n", u.machine, u.release, base ? "available" : "unavailable (CO-RE capture requires kernel BTF)");
    fprintf(stderr, "kprobe program: %s; ringbuf: %s; stack map: %s\n",
        supported(libbpf_probe_bpf_prog_type(BPF_PROG_TYPE_KPROBE, NULL)),
        supported(libbpf_probe_bpf_map_type(BPF_MAP_TYPE_RINGBUF, NULL)),
        supported(libbpf_probe_bpf_map_type(BPF_MAP_TYPE_STACK_TRACE, NULL)));
    fprintf(stderr, "symbolization: %s\nDWARF/source lines: %s\n",
        symbol_address("_stext") ? "kernel symbols+offset available" : "addresses hidden or unavailable",
        rs_source_open(vmlinux, "/sys/kernel/notes", symbol_address("_stext")));
    if (base && !probe_trampoline("__fput", false)) fprintf(stderr, "fentry: available (load-verified, representative __fput)\n");
    else fprintf(stderr, "fentry: unavailable or representative target/permissions unsuitable\n");
    if (base && !probe_trampoline("__fput", true)) fprintf(stderr, "fexit: available (load-verified, representative __fput; return capture not requested)\n");
    else fprintf(stderr, "fexit: unavailable or representative target/permissions unsuitable\n");
}
static bool validate_btf(struct btf *btf, const struct rs_target *t)
{
    int id = btf__find_by_name_kind(btf, t->function, BTF_KIND_FUNC);
    if (id < 0) return false;
    const struct btf_type *fn = btf__type_by_id(btf, id);
    const struct btf_type *proto = btf__type_by_id(btf, fn->type);
    if (!proto || !btf_is_func_proto(proto)) fail("invalid BTF function prototype");
    unsigned n = btf_vlen(proto);
    if (t->object_arg >= n || (t->reason_arg >= 0 && (unsigned)t->reason_arg >= n)) fail("target argument index exceeds BTF prototype");
    const struct btf_param *args = btf_params(proto);
    unsigned last = t->reason_arg > (int)t->object_arg ? (unsigned)t->reason_arg : t->object_arg;
    for (unsigned i = 0; i <= last; i++) {
        int resolved = btf__resolve_type(btf, args[i].type);
        const struct btf_type *arg = resolved < 0 ? NULL : btf__type_by_id(btf, resolved);
        long long size = btf__resolve_size(btf, args[i].type);
        if (!arg || !(btf_is_ptr(arg) || btf_is_int(arg) || btf_is_enum(arg) || btf_is_enum64(arg)) || size <= 0 || size > 8)
            fail("selected argument follows an unsupported multi-register/aggregate ABI argument");
    }
    int obj = btf__resolve_type(btf, args[t->object_arg].type);
    if (obj < 0 || !btf_is_ptr(btf__type_by_id(btf, obj))) fail("object argument is not a pointer in BTF");
    if (t->reason_arg >= 0) {
        int reason = btf__resolve_type(btf, args[t->reason_arg].type);
        const struct btf_type *r = reason < 0 ? NULL : btf__type_by_id(btf, reason);
        if (!r || !(btf_is_int(r) || btf_is_enum(r) || btf_is_enum64(r)) || btf__resolve_size(btf, args[t->reason_arg].type) > 8)
            fail("reason argument must be a scalar integer or enum up to 64 bits");
    }
    return true;
}
static bool resolve_target(const struct rs_target *t, struct btf *base)
{
    unsigned matches = 0;
    for (size_t i = 0; i < nsymbols; i++) if (!strcmp(t->function, symbols[i].name)) matches++;
    if (!matches) { fprintf(stderr, "refscope: target '%s' not found in kernel symbols\n", t->function); exit(2); }
    if (matches != 1) fail("ambiguous function name in kallsyms");
    bool valid = base && validate_btf(base, t);
    if (!valid && base) {
        const char *module_name = NULL;
        for (size_t i = 0; i < nsymbols; i++)
            if (!strcmp(t->function, symbols[i].name)) module_name = symbols[i].module;
        if (module_name) {
            struct btf *module = btf__load_module_btf(module_name, base);
            if (!libbpf_get_error(module)) { valid = validate_btf(module, t); btf__free(module); }
        }
    }
    fprintf(stderr, "target %s: symbol present; arguments %s; attach eligibility unverified until load\n", t->function, valid ? "BTF-validated" : "ABI-only (no BTF prototype)");
    return valid;
}
static int prepare_one(unsigned i, bool fentry, struct trace_bpf *map_source)
{
    struct trace_bpf *s = trace_bpf__open();
    if (!s) return -errno;
    for (size_t j = 0; j < nsymbols; j++)
        if (!strcmp(symbols[j].name, targets[i].function)) s->rodata->target_ip = symbols[j].address;
    s->rodata->object_arg = targets[i].object_arg; s->rodata->reason_arg = targets[i].reason_arg;
    s->rodata->target_id = i; s->rodata->event_type = targets[i].type;
    s->rodata->stacks_enabled = !no_stacks;
    s->rodata->filter_pid = pid_filter; s->rodata->filter_tid = tid_filter;
    s->rodata->filter_object = object_filter;
    memcpy((void *)s->rodata->filter_comm, comm_filter, 16);
    s->rodata->filter_cpus = cpu_filter;
    memcpy((void *)s->rodata->cpu_allowed, cpus, sizeof(cpus));
    int err = bpf_map__set_max_entries(s->maps.events, dry ? (unsigned)sysconf(_SC_PAGESIZE) : ring_size);
    if (err) goto fail;
    struct trace_bpf *source = map_source ? map_source : (i ? probes[0] : NULL);
    if (source) {
        if ((err = bpf_map__reuse_fd(s->maps.events, bpf_map__fd(source->maps.events))) ||
            (err = bpf_map__reuse_fd(s->maps.stats, bpf_map__fd(source->maps.stats))) ||
            (err = bpf_map__reuse_fd(s->maps.stacks, bpf_map__fd(source->maps.stacks)))) goto fail;
    }
    if ((err = bpf_program__set_autoload(s->progs.capability_fexit, false)) ||
        (err = bpf_program__set_autoload(s->progs.capture_fentry, fentry)) ||
        (err = bpf_program__set_autoload(s->progs.capture_kprobe, !fentry))) goto fail;
    if (fentry && (err = bpf_program__set_attach_target(s->progs.capture_fentry, 0, targets[i].function))) goto fail;
    if ((err = trace_bpf__load(s))) goto fail;
    probes[i] = s;
    selected_fentry[i] = fentry;
    fprintf(stderr, "target %s: selected backend %s (BPF load verified; not attached yet)\n", targets[i].function, fentry ? "fentry" : "kprobe");
    return 0;
fail:
    trace_bpf__destroy(s);
    return err;
}
static int attach_one(unsigned i)
{
    struct trace_bpf *s = probes[i];
    struct bpf_link *link = selected_fentry[i] ? bpf_program__attach_trace(s->progs.capture_fentry) :
        bpf_program__attach_kprobe(s->progs.capture_kprobe, false, targets[i].function);
    int err = libbpf_get_error(link);
    if (err) return err;
    links[i] = link;
    return 0;
}
static void detach_all(void)
{
    for (unsigned i = 0; i < ntargets; i++) {
        if (!links[i]) continue;
        /* Link-specific misses must be read while the link FD still exists.
         * Detach first if supported; otherwise this is a documented final snapshot. */
        int detached = bpf_link__detach(links[i]);
        if (!selected_fentry[i]) {
            struct bpf_link_info info = {}; __u32 size = sizeof(info);
            if (bpf_obj_get_info_by_fd(bpf_link__fd(links[i]), &info, &size) ||
                info.type != BPF_LINK_TYPE_PERF_EVENT || info.perf_event.type != BPF_PERF_EVENT_KPROBE ||
                size < offsetof(struct bpf_link_info, perf_event.kprobe.missed) + sizeof(info.perf_event.kprobe.missed)) {
                kprobe_misses_known = false;
            } else kprobe_misses += info.perf_event.kprobe.missed;
        }
        if (detached) miss_snapshot = true;
        if (detached) fprintf(stderr, "target %s: kernel miss count is a pre-close snapshot (detach API unsupported)\n", targets[i].function);
        bpf_link__destroy(links[i]); links[i] = NULL;
        struct bpf_prog_info info = {}; __u32 size = sizeof(info);
        int fd = bpf_program__fd(selected_fentry[i] ? probes[i]->progs.capture_fentry : probes[i]->progs.capture_kprobe);
        if (bpf_obj_get_info_by_fd(fd, &info, &size) || size < offsetof(struct bpf_prog_info, recursion_misses) + sizeof(info.recursion_misses))
            recursion_known = false;
        else recursion_misses += info.recursion_misses;
    }
}
static double now(void)
{
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
static int run_offline_cli(int argc, char **argv, const char *relative_script, const char *error_label)
{
    char executable[PATH_MAX];
    char script[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    if (length < 0 || (size_t)length >= sizeof(executable) - 1) {
        fprintf(stderr, "refscope: cannot locate timeline engine: %s\n", strerror(errno));
        return 2;
    }
    executable[length] = 0;
    char *slash = strrchr(executable, '/');
    if (!slash) {
        fprintf(stderr, "refscope: cannot locate timeline engine\n");
        return 2;
    }
    *slash = 0;
    slash = strrchr(executable, '/');
    if (!slash) {
        fprintf(stderr, "refscope: timeline engine layout is invalid\n");
        return 2;
    }
    *slash = 0;
    if (snprintf(script, sizeof(script), "%s/src/%s", executable, relative_script) >=
            (int)sizeof(script) || access(script, R_OK) != 0) {
        fprintf(stderr, "refscope: offline %s engine is unavailable: %s\n", error_label, script);
        return 2;
    }
    char module_path[PATH_MAX];
    if (snprintf(module_path, sizeof(module_path), "%s/src", executable) >=
            (int)sizeof(module_path)) {
        fprintf(stderr, "refscope: offline module path is too long\n");
        return 2;
    }
    if (setenv("PYTHONPATH", module_path, 1) != 0) {
        fprintf(stderr, "refscope: cannot configure offline engine: %s\n", strerror(errno));
        return 2;
    }
    char **python_argv = calloc((size_t)argc + 1, sizeof(*python_argv));
    if (!python_argv) {
        fprintf(stderr, "refscope: out of memory\n");
        return 2;
    }
    python_argv[0] = (char *)"python3";
    python_argv[1] = script;
    for (int i = 2; i < argc; i++)
        python_argv[i] = argv[i];
    execvp("python3", python_argv);
    fprintf(stderr, "refscope: cannot start timeline engine: %s\n", strerror(errno));
    free(python_argv);
    return 2;
}

int main(int argc, char **argv)
{
    enum { GET = 1000, PUT, CREATE, FREE, DURATION, FORMAT, DRY, STACKS, PID, TID, COMM, OBJECT, CPU, BACKEND, RING, VMLINUX };
    static const struct option options[] = {
        {"get", 1, 0, GET}, {"put", 1, 0, PUT}, {"create", 1, 0, CREATE}, {"free", 1, 0, FREE},
        {"duration", 1, 0, DURATION}, {"format", 1, 0, FORMAT}, {"dry-run", 0, 0, DRY},
        {"no-stacks", 0, 0, STACKS}, {"pid", 1, 0, PID}, {"tid", 1, 0, TID},
        {"comm", 1, 0, COMM}, {"object", 1, 0, OBJECT}, {"cpu", 1, 0, CPU},
        {"vmlinux", 1, 0, VMLINUX}, {"backend", 1, 0, BACKEND}, {"ring-size", 1, 0, RING}, {"help", 0, 0, 'h'}, {0}
    };
    if (argc == 2 && !strcmp(argv[1], "--help")) { usage(); return 0; }
    if (argc >= 2 && !strcmp(argv[1], "timeline"))
        return run_offline_cli(argc, argv, "timeline/cli.py", "timeline");
    if (argc >= 2 && !strcmp(argv[1], "diagnose"))
        return run_offline_cli(argc, argv, "diagnosis/cli.py", "diagnosis");
    if (argc >= 2 && !strcmp(argv[1], "inspect-target"))
        return run_offline_cli(argc, argv, "provenance/inspector.py", "target inspector");
    if (argc >= 2 && !strcmp(argv[1], "syzbot"))
        return run_offline_cli(argc, argv, "syzbot/cli.py", "syzbot intake");
    if (argc >= 2 && !strcmp(argv[1], "trace")) {
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--target-spec") || !strncmp(argv[i], "--target-spec=", 14))
                return run_offline_cli(argc, argv, "provenance/target_adapter.py", "target adapter");
        }
    }
    if (argc < 2 || (strcmp(argv[1], "trace") && strcmp(argv[1], "doctor"))) { usage(); return 2; }
    doctor = !strcmp(argv[1], "doctor");
    if (doctor) dry = true;
    optind = 2; int c;
    while ((c = getopt_long(argc, argv, "h", options, NULL)) != -1) {
        char error[512], *end;
        switch (c) {
        case GET: case PUT: case CREATE: case FREE:
            if (ntargets == MAX_TARGETS) fail("at most 32 targets supported");
            if (rs_parse_target(optarg, c - GET, &targets[ntargets], error, sizeof(error))) fail(error);
            for (unsigned i = 0; i < ntargets; i++) if (!strcmp(targets[i].function, targets[ntargets].function)) fail("duplicate target function");
            ntargets++; break;
        case DURATION:
            errno = 0; duration = strtod(optarg, &end);
            if (errno || end == optarg || (*end && strcmp(end, "s")) || !(duration > 0 && duration <= 86400)) fail("duration must be in (0, 86400] seconds");
            break;
        case FORMAT:
            if (strcmp(optarg, "text") && strcmp(optarg, "jsonl")) fail("format must be text or jsonl");
            json = !strcmp(optarg, "jsonl"); break;
        case DRY: dry = true; break;
        case STACKS: no_stacks = true; break;
        case PID: pid_filter = number(optarg, UINT_MAX); if (!pid_filter) fail("PID must be positive"); break;
        case TID: tid_filter = number(optarg, UINT_MAX); if (!tid_filter) fail("TID must be positive"); break;
        case OBJECT: object_filter = number(optarg, ULLONG_MAX); if (!object_filter) fail("object must be nonzero"); break;
        case COMM: if (!*optarg || strlen(optarg) > 15) fail("comm must contain 1..15 bytes"); strcpy(comm_filter, optarg); break;
        case CPU: parse_cpus(optarg); break;
        case BACKEND: backend = optarg; if (strcmp(backend, "auto") && strcmp(backend, "fentry") && strcmp(backend, "kprobe")) fail("backend must be auto, fentry or kprobe"); break;
        case RING: {
            long page_size = sysconf(_SC_PAGESIZE);
            if (page_size <= 0)
                fail("cannot determine system page size");
            ring_size = number(optarg, 1U << 30);
            if (ring_size < (unsigned long)page_size ||
                (ring_size & (ring_size - 1)))
                fail("ring size must be a power of two and at least one page");
            break;
        }
        case VMLINUX: vmlinux = optarg; break;
        case 'h': usage(); return 0;
        default: return 2;
        }
    }
    if (optind != argc || (!ntargets && !doctor)) fail("provide at least one target and no positional arguments");
    load_symbols();
    struct btf *base = btf__load_vmlinux_btf();
    if (libbpf_get_error(base)) base = NULL;
    libbpf_set_print(quiet_libbpf);
    report_capabilities(base);
    if (doctor && !ntargets) { btf__free(base); rs_source_close(); return 0; }
    if (!base) fail("kernel BTF unavailable: CO-RE capture/argument validation cannot proceed on this kernel");
    bool has_btf[MAX_TARGETS];
    for (unsigned i = 0; i < ntargets; i++) has_btf[i] = resolve_target(&targets[i], base);
    btf__free(base);
    if (!symbol_address("_stext")) fail("kernel addresses hidden: run with root/BPF/perf privileges and readable kallsyms");
    signal(SIGINT, signal_stop); signal(SIGTERM, signal_stop); signal(SIGPIPE, SIG_IGN);
    int err = 0; struct ring_buffer *ring = NULL;
    int kprobe_blacklist[MAX_TARGETS] = {};
    for (unsigned i = 0; i < ntargets; i++) {
        int ftrace = ftrace_listed(targets[i].function);
        int blacklist = kprobe_blacklisted(targets[i].function);
        kprobe_blacklist[i] = blacklist;
        bool fentry = strcmp(backend, "kprobe") && has_btf[i] && ftrace != 0;
        fprintf(stderr, "target %s: ftrace=%s; kprobe blacklist=%s\n", targets[i].function,
            ftrace == 1 ? "listed" : ftrace == 0 ? "not listed" : "unreadable; kernel load is authoritative",
            blacklist == 1 ? "blocked" : blacklist == 0 ? "clear" : "unreadable; attach may still be rejected");
        if (!fentry && strcmp(backend, "kprobe")) {
            fprintf(stderr, "fentry unavailable for %s: %s\n", targets[i].function,
                !has_btf[i] ? "function not present in BTF" : "function not ftrace-visible");
            if (!strcmp(backend, "fentry")) { err = -ENOTSUP; goto cleanup; }
            fprintf(stderr, "falling back to kprobe\n");
        }
        if (!fentry && blacklist == 1) { err = -ENOTSUP; goto cleanup; }
        err = prepare_one(i, fentry, NULL);
        if (err && fentry && !strcmp(backend, "auto") && blacklist != 1) {
            fprintf(stderr, "fentry load unavailable for %s (%s); falling back to kprobe\n", targets[i].function, strerror(-err));
            err = prepare_one(i, false, NULL);
        }
        if (err) { fprintf(stderr, "cannot prepare %s: %s (check BPF/perf permissions, BTF and kernel features)\n", targets[i].function, strerror(-err)); goto cleanup; }
    }
    if (dry) { fprintf(stderr, "dry-run: all targets resolved and BPF-loaded; no probes attached. Attach-time kernel races/policies can still reject attachment.\n"); goto cleanup; }
    for (unsigned i = 0; i < ntargets; i++) {
        if ((err = attach_one(i))) {
            int attach_err = err;
            fprintf(stderr, "attach rejected for %s: %s; releasing all previously attached targets\n", targets[i].function, strerror(-attach_err));
            if (selected_fentry[i] && !strcmp(backend, "auto") && kprobe_blacklist[i] != 1) {
                struct trace_bpf *old = probes[i];
                fprintf(stderr, "fentry attach unavailable for %s (%s); falling back to kprobe\n", targets[i].function, strerror(-attach_err));
                err = prepare_one(i, false, old);
                if (!err) {
                    trace_bpf__destroy(old);
                    err = attach_one(i);
                    if (!err) fprintf(stderr, "target %s: selected fallback backend kprobe\n", targets[i].function);
                }
            }
            if (err) goto cleanup;
        }
    }
    ring = ring_buffer__new(bpf_map__fd(probes[0]->maps.events), on_event, NULL, NULL);
    if (!ring) { err = -errno; goto cleanup; }
    fprintf(stderr, "ready\n");
    double deadline = now() + duration;
    while (!stopping && now() < deadline) {
        err = ring_buffer__poll(ring, 50);
        if (err == -EINTR) { err = 0; continue; }
        if (err < 0) break;
        err = 0;
    }
    detach_all();
    if (!err) { int result = ring_buffer__consume(ring); if (result < 0) err = result; }
    emit_stacks();
    int ncpu = libbpf_num_possible_cpus();
    struct rs_stats *stats = ncpu > 0 ? calloc(ncpu, sizeof(*stats)) : NULL;
    __u32 key = 0;
    unsigned long long attempted = 0;
    unsigned long long ring_dropped = 0;
    unsigned long long nested_dropped = 0;
    unsigned long long stack_errors = 0;
    unsigned long long dropped = 0;
    double rate = 0;
    bool counters_known = true;

    if (!stats ||
        bpf_map_lookup_elem(bpf_map__fd(probes[0]->maps.stats),
                            &key, stats)) {
        counters_known = false;
        fprintf(stderr, "loss counters unavailable\n");
        if (!err)
            err = -EIO;
    }

    if (counters_known) {
        for (int i = 0; i < ncpu; i++) {
            if (ULLONG_MAX - attempted < stats[i].attempted ||
                ULLONG_MAX - ring_dropped < stats[i].ring_dropped ||
                ULLONG_MAX - nested_dropped < stats[i].nested_dropped ||
                ULLONG_MAX - stack_errors < stats[i].stack_errors) {
                counters_known = false;
                fprintf(stderr, "loss counter aggregation overflow\n");
                if (!err)
                    err = -EOVERFLOW;
                break;
            }

            attempted += stats[i].attempted;
            ring_dropped += stats[i].ring_dropped;
            nested_dropped += stats[i].nested_dropped;
            stack_errors += stats[i].stack_errors;
        }
    }

    if (counters_known) {
        if (ULLONG_MAX - ring_dropped < nested_dropped) {
            counters_known = false;
            fprintf(stderr, "loss counter aggregation overflow\n");
            if (!err)
                err = -EOVERFLOW;
        } else {
            dropped = ring_dropped + nested_dropped;
            rate = attempted ? 100.0 * dropped / attempted : 0;
        }
    }

    bool accounting_consistent =
        counters_known &&
        dropped <= attempted &&
        captured == attempted - dropped;

    /*
     * This only describes RefScope's ring transport accounting.
     * It deliberately does not claim that kernel probe misses are known.
     */
    bool transport_complete =
        counters_known &&
        !err &&
        accounting_consistent;

    bool incomplete =
        !counters_known ||
        (counters_known && dropped != 0) ||
        (counters_known && stack_errors != 0) ||
        stack_lookup_errors != 0 ||
        !transport_complete || ordering_errors || !recursion_known || !kprobe_misses_known || recursion_misses || kprobe_misses;

    const char *used = selected_fentry[0] ? "fentry" : "kprobe";
    for (unsigned i = 1; i < ntargets; i++) if (selected_fentry[i] != selected_fentry[0]) used = "mixed";
    if (json) {
        printf("{\"record\":\"summary\",\"schema_version\":1,"
               "\"captured\":%llu,"
               "\"loss_counters_known\":%s,",
               captured,
               counters_known ? "true" : "false");

        if (counters_known) {
            printf("\"attempted\":%llu,\"dropped\":%llu,"
                   "\"drop_rate\":%.6f,"
                   "\"ring_dropped\":%llu,"
                   "\"nested_dropped\":%llu,"
                   "\"stack_errors\":%llu,",
                   attempted, dropped, rate,
                   ring_dropped, nested_dropped, stack_errors);
        } else {
            printf("\"attempted\":null,\"dropped\":null,"
                   "\"drop_rate\":null,"
                   "\"ring_dropped\":null,"
                   "\"nested_dropped\":null,"
                   "\"stack_errors\":null,");
        }

        printf("\"userspace_stack_lookup_errors\":%llu,\"ordering_errors\":%llu,", stack_lookup_errors, ordering_errors);
        printf("\"kernel_recursion_misses\":");
        if (recursion_known) printf("%llu", recursion_misses); else printf("null");
        printf(",\"kprobe_misses\":");
        if (kprobe_misses_known) printf("%llu", kprobe_misses); else printf("null");
        printf(",\"kernel_miss_snapshot\":%s,\"ring_size\":%u,\"backend\":\"%s\",\"stacks_enabled\":%s,\"transport_complete\":%s,\"incomplete\":%s}\n",
               miss_snapshot ? "true" : "false", ring_size, used, no_stacks ? "false" : "true",
               transport_complete ? "true" : "false", incomplete ? "true" : "false");
    }
    fprintf(stderr, "ring size: %u; backend: %s; stacks: %s; incomplete: %s; ordering errors: %llu\n",
            ring_size, used, no_stacks ? "disabled" : "enabled", incomplete ? "yes" : "no", ordering_errors);

    if (counters_known) {
        fprintf(stderr,
                "events captured: %llu; dropped: %llu "
                "(ring: %llu, nested: %llu); "
                "drop rate: %.6f%%; stack errors: %llu; "
                "userspace stack lookup errors: %llu; "
                "kernel miss counters: see summary\n",
                captured, dropped, ring_dropped, nested_dropped,
                rate, stack_errors, stack_lookup_errors);
    } else {
        fprintf(stderr,
                "events captured: %llu; loss counters: unknown; "
                "userspace stack lookup errors: %llu; "
                "kernel miss counters: see summary\n",
                captured, stack_lookup_errors);
    }

    if ((!transport_complete || ordering_errors) && !err)
        err = -EIO;

    free(stats);
    if (fflush(stdout)) err = -EIO;
cleanup:
    detach_all();
    ring_buffer__free(ring);
    rs_source_close();
    for (unsigned i = 0; i < ntargets; i++) { bpf_link__destroy(links[i]); trace_bpf__destroy(probes[i]); }
    for (size_t i = 0; i < nsymbols; i++) { free(symbols[i].name); free(symbols[i].module); }
    free(symbols);
    if (err) fprintf(stderr, "capture failed: %s\n", strerror(-err));
    return err ? 1 : 0;
}
