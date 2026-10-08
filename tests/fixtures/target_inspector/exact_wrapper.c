#include <linux/refcount.h>
struct foo { refcount_t refs; };
void foo_get(struct foo *foo) { refcount_inc(&foo->refs); }
void foo_put(struct foo *foo) { refcount_dec(&foo->refs); }
