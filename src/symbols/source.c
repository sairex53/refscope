#include "refscope/source.h"
#ifdef RS_HAVE_LIBDW
#include <elfutils/libdwfl.h>
#include <elfutils/libdwelf.h>
#include <fcntl.h>
#include <gelf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static Dwfl *dwfl;
static Dwfl_Module *module;
static uint64_t runtime_start, elf_start, elf_text_end;
/* Read bounded, host-endian kernel notes, not DWARF. Both supported targets
 * execute native-endian. Reject malformed lengths before any pointer arithmetic. */
static int note_id(const char *path, unsigned char id[64])
{
    unsigned char data[65536];
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(data, 1, sizeof(data), f);
    bool bad = ferror(f) || !feof(f);
    fclose(f);
    if (bad) return -1;
    size_t p = 0;
    while (n - p >= 12) {
        uint32_t h[3]; memcpy(h, data + p, 12); p += 12;
        size_t name = ((size_t)h[0] + 3) & ~(size_t)3;
        size_t desc = ((size_t)h[1] + 3) & ~(size_t)3;
        if (name > n-p || desc > n-p-name) return -1;
        if (h[2] == NT_GNU_BUILD_ID && h[0] == 4 && !memcmp(data+p, "GNU", 4) && h[1] && h[1] <= 64) {
            memcpy(id, data+p+name, h[1]); return h[1];
        }
        p += name + desc;
    }
    return -1;
}
static int no_external_debug(Dwfl_Module *mod, void **user, const char *name,
    Dwarf_Addr base, const char *file, const char *link, GElf_Word crc, char **out)
{
    (void)mod; (void)user; (void)name; (void)base; (void)file;
    (void)link; (void)crc; (void)out;
    return -1;
}
void rs_source_close(void)
{
    if (dwfl) dwfl_end(dwfl);
    dwfl = NULL; module = NULL; runtime_start = elf_start = elf_text_end = 0;
}
const char *rs_source_open(const char *path, const char *notes, uint64_t runtime_text)
{
    rs_source_close();
    if (!path) return "disabled (no --vmlinux; symbol+offset fallback)";
    if (!runtime_text) return "unavailable (runtime _stext hidden; symbol+offset fallback)";
    if (elf_version(EV_CURRENT) == EV_NONE) return "unavailable (libelf initialization)";
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "unavailable (cannot open vmlinux; symbol+offset fallback)";
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    unsigned char id[64]; const void *build_id = NULL;
    int len = note_id(notes, id);
    ssize_t elf_len = elf ? dwelf_elf_gnu_build_id(elf, &build_id) : -1;
    bool match = len > 0 && len == elf_len && !memcmp(id, build_id, len);
    if (elf) elf_end(elf);
    close(fd);
    if (!match) return "unavailable (build ID mismatch or missing; symbol+offset fallback)";
    /* No external debuginfod lookup, no network and no implicit different file. */
    static const Dwfl_Callbacks callbacks = { .section_address = dwfl_offline_section_address, .find_debuginfo = no_external_debug };
    dwfl = dwfl_begin(&callbacks);
    if (!dwfl) return "unavailable (DWFL allocation)";
    module = dwfl_report_offline(dwfl, "vmlinux", path, -1);
    if (!module || dwfl_report_end(dwfl, NULL, NULL)) goto unavailable;
    Dwarf_Addr bias;
    if (!dwfl_module_getdwarf(module, &bias)) goto unavailable;
    int count = dwfl_module_getsymtab(module);
    for (int i = 0; i < count; i++) {
        GElf_Sym sym; const char *name = dwfl_module_getsym(module, i, &sym, NULL);
        if (name && !strcmp(name, "_stext")) elf_start = sym.st_value;
        if (name && !strcmp(name, "_etext")) elf_text_end = sym.st_value;
    }
    if (!elf_start || elf_text_end <= elf_start || !runtime_text) goto unavailable;
    runtime_start = runtime_text;
    return "available (matching build ID; DWARF loaded; lookup deferred until capture drains)";
unavailable:
    rs_source_close();
    return "unavailable (matching build ID, but no usable DWARF/text bounds; symbol+offset fallback)";
}
bool rs_source_lookup(uint64_t ip, const char **file, int *line)
{
    if (!module || ip < runtime_start || ip-runtime_start >= elf_text_end-elf_start) return false;
    Dwfl_Line *src = dwfl_module_getsrc(module, elf_start + (ip-runtime_start));
    if (!src) return false;
    *file = dwfl_lineinfo(src, NULL, line, NULL, NULL, NULL);
    return *file && *line > 0;
}
#else
const char *rs_source_open(const char *vmlinux, const char *notes, uint64_t runtime_text)
{
    (void)vmlinux; (void)notes; (void)runtime_text;
    return "unavailable (built without optional libdw; symbol+offset fallback)";
}
bool rs_source_lookup(uint64_t ip, const char **file, int *line)
{ (void)ip; (void)file; (void)line; return false; }
void rs_source_close(void) {}
#endif
