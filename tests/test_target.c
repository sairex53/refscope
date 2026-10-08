#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "refscope/target.h"
int main(void)
{
    struct rs_target t; char error[512];
    assert(!rs_parse_target("foo_get:obj=arg0,reason=arg1", 0, &t, error, sizeof(error)));
    assert(!strcmp(t.function, "foo_get") && t.object_arg == 0 && t.reason_arg == 1);
    assert(!rs_parse_target("foo.put:obj=arg4", 1, &t, error, sizeof(error)) && t.reason_arg == -1);
    const char *bad[] = {"", "foo", ":obj=arg0", "foo:obj=arg", "foo:obj=arg5", "foo:obj=arg00", "foo:reason=arg0", "foo:obj=arg0,", "foo:obj=arg0,reason=arg", "foo:obj=arg0,reason=arg10", "foo:obj=arg0,reason=arg1,x=arg2", "foo/x:obj=arg0"};
    for (unsigned i=0; i < sizeof(bad)/sizeof(*bad); i++) assert(rs_parse_target(bad[i], 0, &t, error, sizeof(error)) < 0);
    puts("target parser: passed");
}
