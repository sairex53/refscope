#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "refscope/target.h"
int rs_parse_target(const char *spec, unsigned char type, struct rs_target *out, char *error, size_t size)
{
    struct rs_target t = { .reason_arg = -1, .type = type };
    const char *colon = strchr(spec, ':');
    if (!colon || colon == spec || (size_t)(colon - spec) >= sizeof(t.function)) goto invalid;
    for (const char *p = spec; p < colon; p++)
        if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '.')) goto invalid;
    memcpy(t.function, spec, colon - spec);
    const char *p = colon + 1;
    if (strncmp(p, "obj=arg", 7) || p[7] < '0' || p[7] > '4') goto invalid;
    t.object_arg = p[7] - '0'; p += 8;
    if (*p) {
        if (strncmp(p, ",reason=arg", 11) || p[11] < '0' || p[11] > '4' || p[12]) goto invalid;
        t.reason_arg = p[11] - '0';
    }
    *out = t;
    return 0;
invalid:
    snprintf(error, size, "invalid target '%s': expected function:obj=arg0[,reason=arg1]; supported arguments arg0..arg4", spec);
    return -1;
}
