#ifndef REFSCOPE_TARGET_H
#define REFSCOPE_TARGET_H
#include <stddef.h>
struct rs_target { char function[128]; unsigned object_arg; int reason_arg; unsigned char type; };
int rs_parse_target(const char *spec, unsigned char type, struct rs_target *out, char *error, size_t size);
#endif
