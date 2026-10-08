#ifndef REFSCOPE_SOURCE_H
#define REFSCOPE_SOURCE_H
#include <stdbool.h>
#include <stdint.h>
/* Optional libdw backend. notes is a raw ELF-note file, normally /sys/kernel/notes. */
const char *rs_source_open(const char *vmlinux, const char *notes, uint64_t runtime_text);
bool rs_source_lookup(uint64_t ip, const char **file, int *line);
void rs_source_close(void);
#endif
