#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
/* External test-only injection. No fault switches in the production binary. */
static int hit(const char *name) { const char *mode=getenv("RS_TEST_FAULT"); return mode && !strcmp(mode,name); }
static void log_attach(const char *kind)
{
    const char *path = getenv("RS_TEST_ATTACH_LOG");
    if (!path) return;
    FILE *f = fopen(path, "a");
    if (f) { fprintf(f, "%s\n", kind); fclose(f); }
}
struct bpf_link *bpf_program__attach_trace(const struct bpf_program *p)
{
    static int n;
    log_attach("fentry");
    ++n;
    if (hit("partial-attach") && n==2) { errno=EPERM; return NULL; }
    if (hit("fentry-attach-first") && n==1) { errno=EPERM; return NULL; }
    if (hit("fentry-attach-second") && n==2) { errno=EPERM; return NULL; }
    if (hit("fentry-second-kprobe") && n==2) { errno=EPERM; return NULL; }
    struct bpf_link *(*real)(const struct bpf_program *)=dlsym(RTLD_NEXT,"bpf_program__attach_trace");
    return real(p);
}
struct bpf_link *bpf_program__attach_kprobe(const struct bpf_program *p, bool retprobe, const char *func_name)
{
    log_attach("kprobe");
    if (hit("fentry-second-kprobe")) { errno=EPERM; return NULL; }
    struct bpf_link *(*real)(const struct bpf_program *, bool, const char *)=dlsym(RTLD_NEXT,"bpf_program__attach_kprobe");
    return real(p, retprobe, func_name);
}
struct ring_buffer *ring_buffer__new(int fd,ring_buffer_sample_fn fn,void *ctx,const struct ring_buffer_opts *opts)
{
    if (hit("ring-new")) { errno=ENOMEM; return NULL; }
    struct ring_buffer *(*real)(int,ring_buffer_sample_fn,void *,const struct ring_buffer_opts *)=dlsym(RTLD_NEXT,"ring_buffer__new");
    return real(fd,fn,ctx,opts);
}
int ring_buffer__poll(struct ring_buffer *r,int timeout)
{
    static int n;
    if (hit("poll-error")) return -EIO;
    if (hit("poll-eintr") && n++==0) return -EINTR;
    int (*real)(struct ring_buffer *,int)=dlsym(RTLD_NEXT,"ring_buffer__poll"); return real(r,timeout);
}
int ring_buffer__consume(struct ring_buffer *r)
{
    if (hit("consume-error")) return -EIO;
    int (*real)(struct ring_buffer *)=dlsym(RTLD_NEXT,"ring_buffer__consume"); return real(r);
}
int bpf_map_lookup_elem(int fd,const void *key,void *value)
{
    struct bpf_map_info info={}; __u32 size=sizeof(info);
    if (!bpf_obj_get_info_by_fd(fd,&info,&size)) {
        if ((hit("stats-read") && !strcmp(info.name,"stats")) || (hit("stack-read") && !strcmp(info.name,"stacks"))) { errno=EIO; return -1; }
    }
    int (*real)(int,const void *,void *)=dlsym(RTLD_NEXT,"bpf_map_lookup_elem"); return real(fd,key,value);
}
int bpf_obj_get_info_by_fd(int fd, void *info, __u32 *info_len)
{
    static unsigned int perf_info_calls;
    int (*real)(int,void *,__u32 *)=dlsym(RTLD_NEXT,"bpf_obj_get_info_by_fd");
    int rc=real(fd,info,info_len);
    if (!rc && hit("link-info") && info && info_len &&
        *info_len >= sizeof(struct bpf_link_info) &&
        ((struct bpf_link_info *)info)->type == BPF_LINK_TYPE_PERF_EVENT &&
        ++perf_info_calls >= 3) {
        errno=EIO;
        return -1;
    }
    return rc;
}
int bpf_map__reuse_fd(struct bpf_map *map,int fd)
{
    if (hit("reuse")) return -EMFILE;
    int (*real)(struct bpf_map *,int)=dlsym(RTLD_NEXT,"bpf_map__reuse_fd"); return real(map,fd);
}
int bpf_object__load_skeleton(struct bpf_object_skeleton *s)
{
    /* Capability loads are intentionally included in count; identify second
     * real target through its shared maps (first map FD reused by prepare). */
    static int n;
    if (hit("load") && ++n==4) return -ENOMEM;
    int (*real)(struct bpf_object_skeleton *)=dlsym(RTLD_NEXT,"bpf_object__load_skeleton"); return real(s);
}

struct btf *btf__load_vmlinux_btf(void)
{
    if (hit("no-btf")) { errno=ENOENT; return NULL; }
    struct btf *(*real)(void)=dlsym(RTLD_NEXT,"btf__load_vmlinux_btf"); return real();
}
